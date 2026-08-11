"""Non-public operational recovery for CSR candidate finalization."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from typing import NoReturn, TextIO

from .csr_recovery import (
    CANDIDATE_FINALIZATION_JOURNAL_FIELDS,
    CANDIDATE_SOURCE_PATHS,
    CSR_DB_KEYS,
    CSR_SIGNING_JOURNAL_FIELDS,
    ActivePublicationMode,
    CsrRecoveryError,
    FinalizationJournal,
    FinalizationPhase,
    SigningJournal,
    SigningPhase,
    SigningRecoveryStep,
    parse_finalization_journal,
    parse_signing_journal,
    parse_signing_journal_structure,
    validate_signing_transaction_presence,
)
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
from .operational import (
    acquire_operational_locks,
    detect_layout,
    prepare_control_state,
    require_pki_directory,
    require_program,
    resolve_paths,
)
from .parser import ParseResult
from .persisted_identity import IdentitySentinel
from .persisted_identity import serialize_directory_identity, serialize_file_identity
from .publication import (
    PublicationError,
    TreeReadiness,
    atomic_write_bytes,
    exchange_exact,
    fsync_tree,
    publish_no_clobber,
    replace_exact,
    unlink_exact,
)
from .subprocesses import ProcessResult, run_process


MAX_FINALIZATION_JOURNAL_BYTES = 1024 * 1024
MAX_SIGNING_JOURNAL_BYTES = 1024 * 1024
_TRANSACTION = re.compile(r"csr-[0-9a-f]{32}", re.ASCII)
_MAX_EVIDENCE_BYTES = 16 * 1024 * 1024
_PRIVATE_DIRECTORY = DirectoryPolicy(owner=os.geteuid(), mode=0o700)
_PRIVATE_FILE = FilePolicy(
    owner=os.geteuid(), mode=0o600, links=1, max_size=_MAX_EVIDENCE_BYTES
)
_JOURNAL_POLICY = FilePolicy(
    owner=os.geteuid(),
    mode=0o600,
    links=1,
    max_size=MAX_FINALIZATION_JOURNAL_BYTES,
)
_PROTOCOL_FILE = FilePolicy(
    owner=os.geteuid(), mode=0o600, links=1, max_size=1024 * 1024
)
_RESPONSE_KEY_FILE = FilePolicy(
    owner=os.geteuid(), forbidden_bits=0o077, links=1, max_size=1024 * 1024
)

CSR_SIGNING_RECOVERY_CHECKPOINTS = (
    "signing-journal-loaded",
    "replay-request-before-mutation",
    "replay-request-after-mutation",
    "replay-nonce-before-mutation",
    "replay-nonce-after-mutation",
    "replay-before-evidence",
    "replay-after-evidence",
    "replay-after-journal-rewrite",
    *(point for key in reversed(CSR_DB_KEYS) for point in (
        f"rollback-{key}-before-mutation",
        f"rollback-{key}-after-mutation",
        f"rollback-{key}-before-evidence",
        f"rollback-{key}-after-evidence",
        f"rollback-{key}-after-journal-rewrite",
    )),
    "sensitive-key-before-mutation",
    "sensitive-key-after-mutation",
    "terminal-before-mutation",
    "terminal-after-mutation",
    "terminal-before-evidence",
    "terminal-after-evidence",
    "terminal-after-journal-rewrite",
    "response-signature-before-mutation",
    "response-signature-after-mutation",
    "response-signature-before-evidence",
    "response-signature-after-evidence",
    "response-signature-after-journal-rewrite",
    *(point for kind in ("candidate", "response") for point in (
        f"{kind}-stage-before-mutation",
        f"{kind}-stage-after-mutation",
        f"{kind}-stage-before-evidence",
        f"{kind}-stage-after-evidence",
        f"{kind}-stage-after-journal-rewrite",
    )),
    *(point for kind in ("candidate", "response") for name in (
        "tls.crt", "ca-chain.crt", "fullchain.crt", "response", "response.sig",
        *(("candidate",) if kind == "candidate" else ()),
    ) for point in (
        f"{kind}-{name}-before-mutation",
        f"{kind}-{name}-after-mutation",
    )),
    *(point for kind in ("candidate", "response") for point in (
        f"{kind}-publish-before-mutation",
        f"{kind}-publish-after-mutation",
        f"{kind}-publish-before-evidence",
        f"{kind}-publish-after-evidence",
        f"{kind}-publish-after-journal-rewrite",
        f"{kind}-published",
    )),
    "signing-journal-before-cleanup",
)

CSR_FINALIZATION_RECOVERY_CHECKPOINTS = (
    "journal-written",
    "outcome-before-mutation",
    "outcome-after-mutation",
    "outcome-before-evidence",
    "outcome-after-evidence",
    "outcome-before-journal-rewrite",
    "outcome-after-journal-rewrite",
    "outcome-published",
    "active-before-mutation",
    "active-after-mutation",
    "active-before-evidence",
    "active-after-evidence",
    "active-before-journal-rewrite",
    "active-after-journal-rewrite",
    "active-published",
    "old-active-before-cleanup",
    "old-active-after-cleanup",
    "journal-before-cleanup",
)


def _die(message: str) -> NoReturn:
    raise ApplicationError(message)


def _actual(path: str) -> FileIdentity | object:
    try:
        return identity_at(path)
    except FilesystemError:
        _die("CSR finalization recovery filesystem state could not be inspected")


def _matches(
    actual: FileIdentity | object,
    expected: FileIdentity | FileObjectState | DirectoryIdentity | IdentitySentinel,
) -> bool:
    if expected is IdentitySentinel.ABSENT:
        return actual is ABSENT
    if actual is ABSENT or not isinstance(actual, FileIdentity):
        return False
    if isinstance(expected, FileIdentity):
        return actual == expected
    if isinstance(expected, FileObjectState):
        return actual.state == expected
    if isinstance(expected, DirectoryIdentity):
        return actual.kind == "directory" and actual.directory == expected
    return False


def _file_identity(value: object, field: str) -> FileIdentity:
    if not isinstance(value, FileIdentity):
        raise TypeError(f"{field} must contain a full file identity")
    return value


def _object_state(value: object, field: str) -> FileObjectState:
    if not isinstance(value, FileObjectState):
        raise TypeError(f"{field} must contain a file object state")
    return value


def _directory_identity(value: object, field: str) -> DirectoryIdentity:
    if not isinstance(value, DirectoryIdentity):
        raise TypeError(f"{field} must contain a directory identity")
    return value


def _parent(path: str) -> tuple[OpenedDirectory, str]:
    parent_path, name = os.path.split(path)
    try:
        return OpenedDirectory(parent_path), name
    except FilesystemError:
        _die("CSR finalization recovery publication parent is unsafe")


def _digest_file(
    path: str,
    expected: FileIdentity | FileObjectState,
    expected_digest: str,
    label: str,
) -> FileIdentity:
    data = b""
    identity: FileIdentity | None = None
    try:
        with OpenedFile(
            path,
            policy=_PRIVATE_FILE,
            expected_identity=expected,
        ) as opened:
            data = opened.read(_MAX_EVIDENCE_BYTES)
            identity = opened.identity
    except FilesystemError:
        _die(f"{label} identity changed")
    if hashlib.sha256(data).hexdigest() != expected_digest:
        _die(f"{label} digest changed")
    assert identity is not None
    return identity


def _directory_entries(directory: OpenedDirectory, label: str) -> frozenset[str]:
    try:
        names = frozenset(os.listdir(directory.fileno()))
        directory.recheck()
        return names
    except (OSError, FilesystemError):
        _die(f"{label} has unexpected or unsafe entries")


def _validate_source_directories(journal: FinalizationJournal) -> None:
    groups: dict[str, list[tuple[str, str]]] = {
        "candidate": [],
        "response": [],
        "artifact": [],
    }
    for key, root, name in CANDIDATE_SOURCE_PATHS:
        groups[root].append((key, name))
    roots = {
        "candidate": ("candidate_dir", "candidate_dir_identity"),
        "response": ("response_dir", "response_dir_identity"),
        "artifact": ("artifact_dir", "artifact_dir_identity"),
    }
    for root, members in groups.items():
        path_field, identity_field = roots[root]
        path = journal.path(path_field)
        expected_directory = _directory_identity(
            journal.identity(identity_field), identity_field
        )
        try:
            with OpenedDirectory(
                path,
                policy=_PRIVATE_DIRECTORY,
                expected_identity=expected_directory,
            ) as directory:
                if _directory_entries(directory, f"CSR finalization {root} source") != {
                    name for _key, name in members
                }:
                    _die(
                        f"CSR finalization {root} source has unexpected or unsafe entries"
                    )
                for key, name in members:
                    identity_field = f"source_{key}_identity"
                    digest_field = f"source_{key}_sha256"
                    expected_file = _file_identity(
                        journal.identity(identity_field), identity_field
                    )
                    data = b""
                    try:
                        with directory.open_file(
                            name,
                            policy=_PRIVATE_FILE,
                            expected_identity=expected_file,
                        ) as opened:
                            data = opened.read(_MAX_EVIDENCE_BYTES)
                    except FilesystemError:
                        _die(f"CSR finalization source identity changed: {key}")
                    if hashlib.sha256(data).hexdigest() != journal[digest_field]:
                        _die(f"CSR finalization source digest changed: {key}")
                directory.recheck()
        except FilesystemError:
            _die("CSR finalization source directory identity changed")


def _validate_retained_transaction(journal: FinalizationJournal) -> None:
    identity = _directory_identity(
        journal.identity("transaction_dir_identity"), "transaction_dir_identity"
    )
    try:
        with OpenedDirectory(
            journal.path("transaction_dir"),
            policy=_PRIVATE_DIRECTORY,
            expected_identity=identity,
        ):
            pass
    except FilesystemError:
        _die("CSR finalization retained transaction identity changed")
    _digest_file(
        journal.path("response_trust_path"),
        _file_identity(
            journal.identity("response_trust_identity"), "response_trust_identity"
        ),
        journal["response_trust_sha256"],
        "CSR finalization retained response trust",
    )


_OUTCOME_MEMBERS = (
    ("deployment", "outcome_deployment_identity", "deployment_sha256"),
    (
        "deployment.sig",
        "outcome_deployment_signature_identity",
        "deployment_signature_sha256",
    ),
    ("deployers.allowed_signers", "outcome_deployers_identity", "deployers_sha256"),
    ("decision", "outcome_decision_identity", "decision_sha256"),
)


@dataclass(frozen=True, slots=True)
class _OutcomeState:
    published: bool
    identity: FileIdentity
    readiness: TreeReadiness


def _validate_outcome_at(
    path: str,
    expected_directory: DirectoryIdentity,
    journal: FinalizationJournal,
) -> tuple[FileIdentity, TreeReadiness]:
    parent, name = _parent(path)
    identity: FileIdentity | None = None
    readiness: TreeReadiness | None = None
    try:
        try:
            with parent.open_directory(
                name,
                policy=_PRIVATE_DIRECTORY,
                expected_identity=expected_directory,
            ) as directory:
                if _directory_entries(directory, "CSR finalization outcome") != {
                    member for member, _identity, _digest in _OUTCOME_MEMBERS
                }:
                    _die("CSR finalization outcome has unexpected or unsafe entries")
                for member, identity_field, digest_field in _OUTCOME_MEMBERS:
                    expected_file = _file_identity(
                        journal.identity(identity_field), identity_field
                    )
                    data = b""
                    try:
                        with directory.open_file(
                            member,
                            policy=_PRIVATE_FILE,
                            expected_identity=expected_file,
                        ) as opened:
                            data = opened.read(_MAX_EVIDENCE_BYTES)
                    except FilesystemError:
                        _die(f"CSR finalization outcome identity changed: {member}")
                    if hashlib.sha256(data).hexdigest() != journal[digest_field]:
                        _die(f"CSR finalization outcome digest changed: {member}")
                readiness = fsync_tree(directory, parent, name)
                identity = directory.identity
        except (FilesystemError, PublicationError):
            _die("CSR finalization outcome could not be durably validated")
        assert identity is not None and readiness is not None
        return identity, readiness
    finally:
        parent.close()


def _validate_outcome_state(journal: FinalizationJournal) -> _OutcomeState:
    stage = journal.path("outcome_stage")
    destination = journal.path("outcome_destination")
    stage_actual = _actual(stage)
    destination_actual = _actual(destination)
    expected = _directory_identity(
        journal.identity("outcome_stage_identity"), "outcome_stage_identity"
    )
    stage_present = _matches(stage_actual, expected)
    destination_present = _matches(destination_actual, expected)
    if stage_present == destination_present:
        _die("CSR finalization outcome rename state is inconsistent")
    if stage_actual is not ABSENT and not stage_present:
        _die("CSR finalization outcome stage identity changed")
    if destination_actual is not ABSENT and not destination_present:
        _die("CSR finalization outcome destination identity changed")
    selected = destination if destination_present else stage
    identity, readiness = _validate_outcome_at(selected, expected, journal)
    return _OutcomeState(destination_present, identity, readiness)


@dataclass(frozen=True, slots=True)
class _ActiveState:
    published: bool
    stage_identity: FileIdentity | None
    destination_identity: FileIdentity | None
    old_stage_identity: FileIdentity | None


def _validate_active_state(journal: FinalizationJournal) -> _ActiveState:
    stage = journal.path("active_stage")
    destination = journal.path("active_destination")
    stage_actual = _actual(stage)
    destination_actual = _actual(destination)
    active = _object_state(
        journal.identity("active_stage_identity"), "active_stage_identity"
    )
    predecessor = journal.identity("active_pre_identity")
    if journal.active_mode is ActivePublicationMode.CREATE:
        staged = _matches(stage_actual, active) and destination_actual is ABSENT
        published = stage_actual is ABSENT and _matches(destination_actual, active)
    else:
        predecessor_state = _object_state(predecessor, "active_pre_identity")
        staged = _matches(stage_actual, active) and _matches(
            destination_actual, predecessor_state
        )
        published = _matches(destination_actual, active) and (
            stage_actual is ABSENT or _matches(stage_actual, predecessor_state)
        )
    if staged == published:
        _die("CSR finalization active publication state is inconsistent")

    stage_identity: FileIdentity | None = None
    destination_identity: FileIdentity | None = None
    old_stage_identity: FileIdentity | None = None
    if staged:
        stage_identity = _digest_file(
            stage,
            active,
            journal["active_sha256"],
            "Staged active accepted-evidence pointer",
        )
        if journal.active_mode is ActivePublicationMode.EXCHANGE:
            predecessor_state = _object_state(predecessor, "active_pre_identity")
            destination_identity = _digest_file(
                destination,
                predecessor_state,
                journal["active_pre_sha256"],
                "Pre-finalization active accepted-evidence pointer",
            )
    else:
        destination_identity = _digest_file(
            destination,
            active,
            journal["active_sha256"],
            "Published active accepted-evidence pointer",
        )
        if stage_actual is not ABSENT:
            predecessor_state = _object_state(predecessor, "active_pre_identity")
            old_stage_identity = _digest_file(
                stage,
                predecessor_state,
                journal["active_pre_sha256"],
                "Superseded active accepted-evidence pointer",
            )
    return _ActiveState(
        published,
        stage_identity,
        destination_identity,
        old_stage_identity,
    )


def _validate_phase(
    journal: FinalizationJournal,
    outcome: _OutcomeState,
    active: _ActiveState,
) -> None:
    if journal.phase is FinalizationPhase.PLANNED and active.published:
        _die("Planned CSR finalization journal conflicts with publication state")
    if journal.phase is FinalizationPhase.OUTCOME_PUBLISHED and not outcome.published:
        _die("Outcome-published CSR finalization journal conflicts with outcome state")
    if journal.phase is FinalizationPhase.ACTIVE_PUBLISHED and (
        not outcome.published or not active.published
    ):
        _die("Active-published CSR finalization journal conflicts with publication state")


def _serialize_journal(values: Mapping[str, str], pki_dir: str) -> bytes:
    try:
        data = "".join(
            f"{field}={values[field]}\n"
            for field in CANDIDATE_FINALIZATION_JOURNAL_FIELDS
        ).encode("ascii")
        parse_finalization_journal(data, pki_dir=pki_dir)
        return data
    except (KeyError, UnicodeEncodeError, CsrRecoveryError):
        _die("CSR finalization recovery journal could not be serialized safely")


@dataclass(slots=True)
class _Journal:
    path: str
    pki_dir: str
    values: dict[str, str]
    identity: FileIdentity

    def recheck(self) -> None:
        try:
            with OpenedFile(
                self.path,
                policy=_JOURNAL_POLICY,
                expected_identity=self.identity,
            ):
                pass
        except FilesystemError:
            _die("CSR finalization recovery journal identity changed")

    def write(self) -> None:
        data = _serialize_journal(self.values, self.pki_dir)
        parent, name = _parent(self.path)
        try:
            try:
                result = atomic_write_bytes(
                    parent,
                    name,
                    data,
                    expected_destination=self.identity,
                )
            except (FilesystemError, PublicationError):
                _die("CSR finalization recovery journal could not be rewritten safely")
            identity = getattr(result, "destination_identity", None)
            if identity is None:
                identity = getattr(result, "identity", None)
            if not isinstance(identity, FileIdentity):
                raise TypeError("journal publication returned no file identity")
            self.identity = identity
        finally:
            parent.close()


def _load_journal(path: str, pki_dir: str) -> tuple[_Journal, FinalizationJournal]:
    data = b""
    identity: FileIdentity | None = None
    try:
        with OpenedFile(path, policy=_JOURNAL_POLICY) as opened:
            data = opened.read(MAX_FINALIZATION_JOURNAL_BYTES)
            identity = opened.identity
        record = parse_finalization_journal(data, pki_dir=pki_dir)
    except FilesystemError:
        _die("No safe CSR candidate finalization recovery journal exists")
    except CsrRecoveryError as error:
        _die(str(error))
    assert identity is not None
    return _Journal(path, pki_dir, dict(record.items()), identity), record


def _read_control_state(path: str, label: str) -> dict[str, str]:
    data = b""
    try:
        with OpenedFile(path, policy=_JOURNAL_POLICY) as opened:
            data = opened.read(MAX_FINALIZATION_JOURNAL_BYTES)
    except FilesystemError:
        _die(f"{label} is unsafe")
    values: dict[str, str] = {}
    try:
        lines = data.decode("ascii").split("\n")
    except UnicodeDecodeError:
        _die(f"{label} has invalid content")
    if lines[-1] == "":
        lines.pop()
    for line in lines:
        if "=" not in line:
            _die(f"{label} has invalid content")
        key, value = line.split("=", 1)
        if (
            re.fullmatch(r"[a-z0-9_]+", key, re.ASCII) is None
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
            or key in values
        ):
            _die(f"{label} has invalid content")
        values[key] = value
    return values


def _require_compatible_operational_state(pki_dir: str) -> None:
    if detect_layout(pki_dir) != "generation":
        _die("CSR finalization recovery requires complete generation-aware PKI state")
    signing = f"{pki_dir}/state/csr/recovery-journal"
    marker = f"{pki_dir}/state/rollover/recovery-required"
    rollover = f"{pki_dir}/state/rollover/journal"
    if os.path.lexists(signing):
        _die("Authenticated CSR signing recovery must be completed first")
    if os.path.lexists(marker):
        _die("PKI rollover recovery must be completed first")
    if os.path.lexists(rollover):
        state = _read_control_state(rollover, "PKI recovery journal")
        if (
            state.get("operation") == "rollover-prepare"
            or state.get("committed") != "true"
        ):
            _die("PKI rollover recovery must be completed first")


def _checkpoint(
    point: str,
    fault: FaultHook,
    pause: PauseHook,
) -> None:
    fault(point)
    pause(point)


def _publish_outcome(
    journal: FinalizationJournal,
    state: _OutcomeState,
    control: _Journal,
    fault: FaultHook,
    pause: PauseHook,
) -> None:
    if state.published:
        return
    stage = journal.path("outcome_stage")
    destination = journal.path("outcome_destination")
    source_parent, source_name = _parent(stage)
    destination_parent, destination_name = _parent(destination)
    try:
        _checkpoint("outcome-before-mutation", fault, pause)
        control.recheck()
        try:
            publish_no_clobber(
                source_parent,
                source_name,
                state.identity,
                destination_parent,
                destination_name,
                readiness=state.readiness,
            )
        except PublicationError:
            _die("Cannot publish immutable CSR finalization outcome")
        _checkpoint("outcome-after-mutation", fault, pause)
    finally:
        destination_parent.close()
        source_parent.close()


def _sync_active(
    path: str,
    expected: FileObjectState,
    digest: str,
) -> FileIdentity:
    parent, name = _parent(path)
    try:
        try:
            with parent.open_file(
                name,
                policy=_PRIVATE_FILE,
                expected_identity=expected,
            ) as opened:
                data = opened.read(_MAX_EVIDENCE_BYTES)
                if hashlib.sha256(data).hexdigest() != digest:
                    _die("Published active accepted-evidence pointer digest changed")
                fsync_tree(opened, parent, name)
                return opened.identity
        except (FilesystemError, PublicationError):
            _die("Published active accepted-evidence pointer could not be durably verified")
    finally:
        parent.close()
    raise AssertionError("unreachable")


def _publish_active(
    journal: FinalizationJournal,
    state: _ActiveState,
    control: _Journal,
    fault: FaultHook,
    pause: PauseHook,
) -> None:
    if state.published:
        return
    assert state.stage_identity is not None
    stage = journal.path("active_stage")
    destination = journal.path("active_destination")
    source_parent, source_name = _parent(stage)
    destination_parent, destination_name = _parent(destination)
    try:
        _checkpoint("active-before-mutation", fault, pause)
        control.recheck()
        try:
            if journal.active_mode is ActivePublicationMode.CREATE:
                publish_no_clobber(
                    source_parent,
                    source_name,
                    state.stage_identity,
                    destination_parent,
                    destination_name,
                )
            else:
                assert state.destination_identity is not None
                exchange_exact(
                    source_parent,
                    source_name,
                    state.stage_identity,
                    destination_parent,
                    destination_name,
                    state.destination_identity,
                )
        except PublicationError:
            _die("Cannot publish active accepted-evidence pointer")
        _checkpoint("active-after-mutation", fault, pause)
    finally:
        destination_parent.close()
        source_parent.close()


def _remove_old_active(
    journal: FinalizationJournal,
    control: _Journal,
    fault: FaultHook,
    pause: PauseHook,
) -> None:
    stage = journal.path("active_stage")
    actual = _actual(stage)
    if actual is ABSENT:
        return
    if journal.active_mode is not ActivePublicationMode.EXCHANGE:
        _die("Finalization active-pointer cleanup object is unsafe")
    predecessor = _object_state(
        journal.identity("active_pre_identity"), "active_pre_identity"
    )
    identity = _digest_file(
        stage,
        predecessor,
        journal["active_pre_sha256"],
        "Superseded active accepted-evidence pointer",
    )
    parent, name = _parent(stage)
    try:
        _checkpoint("old-active-before-cleanup", fault, pause)
        control.recheck()
        try:
            unlink_exact(parent, name, identity)
        except PublicationError:
            _die("Cannot remove superseded active pointer stage")
        _checkpoint("old-active-after-cleanup", fault, pause)
    finally:
        parent.close()


def _remove_journal(
    journal: _Journal,
    fault: FaultHook,
    pause: PauseHook,
) -> None:
    journal.recheck()
    parent, name = _parent(journal.path)
    try:
        _checkpoint("journal-before-cleanup", fault, pause)
        try:
            unlink_exact(parent, name, journal.identity)
        except PublicationError:
            _die("Finalization journal changed before terminal cleanup")
    finally:
        parent.close()


def _recover_finalization_locked(
    path: str,
    *,
    transaction: str | None,
    stream: TextIO,
    fault_hook: FaultHook,
    pause_hook: PauseHook,
) -> int:
    journal_path = f"{path}/state/csr/finalization-recovery-journal"

    _require_compatible_operational_state(path)
    control, record = _load_journal(journal_path, path)
    expected_transaction = f"csr-{record['request_id']}"
    if transaction is not None and transaction != expected_transaction:
        _die("CSR recovery transaction does not match the finalization journal")

    _validate_source_directories(record)
    _validate_retained_transaction(record)
    outcome = _validate_outcome_state(record)
    active = _validate_active_state(record)
    _validate_phase(record, outcome, active)
    control.recheck()
    _checkpoint("journal-written", fault_hook, pause_hook)

    if record.phase is FinalizationPhase.PLANNED:
        _publish_outcome(record, outcome, control, fault_hook, pause_hook)
        published_outcome = _validate_outcome_state(record)
        if not published_outcome.published:
            _die("Published finalization outcome identity is inconsistent")
        _checkpoint("outcome-before-evidence", fault_hook, pause_hook)
        control.values["outcome_destination_identity"] = control.values[
            "outcome_stage_identity"
        ]
        control.values["phase"] = FinalizationPhase.OUTCOME_PUBLISHED.value
        _checkpoint("outcome-after-evidence", fault_hook, pause_hook)
        _checkpoint("outcome-before-journal-rewrite", fault_hook, pause_hook)
        control.write()
        _checkpoint("outcome-after-journal-rewrite", fault_hook, pause_hook)
        _checkpoint("outcome-published", fault_hook, pause_hook)

    active = _validate_active_state(record)
    if record.phase is not FinalizationPhase.ACTIVE_PUBLISHED:
        _publish_active(record, active, control, fault_hook, pause_hook)
    active_state = _object_state(
        record.identity("active_stage_identity"), "active_stage_identity"
    )
    _sync_active(
        record.path("active_destination"),
        active_state,
        record["active_sha256"],
    )
    if record.phase is not FinalizationPhase.ACTIVE_PUBLISHED:
        _checkpoint("active-before-evidence", fault_hook, pause_hook)
        control.values["active_destination_identity"] = control.values[
            "active_stage_identity"
        ]
        control.values["phase"] = FinalizationPhase.ACTIVE_PUBLISHED.value
        _checkpoint("active-after-evidence", fault_hook, pause_hook)
        _checkpoint("active-before-journal-rewrite", fault_hook, pause_hook)
        control.write()
        _checkpoint("active-after-journal-rewrite", fault_hook, pause_hook)
        _checkpoint("active-published", fault_hook, pause_hook)

    _remove_old_active(record, control, fault_hook, pause_hook)
    _remove_journal(control, fault_hook, pause_hook)
    print(
        "[OK] Recovered CSR candidate finalization: "
        f"{record['service']}/{record['request_id']}",
        file=stream,
    )
    stream.flush()
    return 0


def recover_finalization(
    pki_dir: os.PathLike[str] | str,
    *,
    transaction: str | None = None,
    environment: Mapping[str, str] | None = None,
    output: TextIO | None = None,
    fault_hook: FaultHook = DEFAULT_FAULT_HOOK,
    pause_hook: PauseHook = DEFAULT_PAUSE_HOOK,
) -> int:
    """Resume one exact candidate-finalization journal under the full lock profile."""

    path = os.fspath(pki_dir)
    if not isinstance(path, str):
        raise TypeError("pki_dir must be a text path")
    if not os.path.isabs(path) or os.path.normpath(path) != path:
        raise ValueError("pki_dir must be an absolute normalized path")
    if transaction is not None and not isinstance(transaction, str):
        raise TypeError("transaction must be text or None")
    if not callable(fault_hook) or not callable(pause_hook):
        raise TypeError("recovery hooks must be callable")
    stream = sys.stdout if output is None else output
    require_pki_directory(path)
    prepare_control_state(path)
    with acquire_operational_locks(path, "export"):
        return _recover_finalization_locked(
            path,
            transaction=transaction,
            stream=stream,
            fault_hook=fault_hook,
            pause_hook=pause_hook,
        )


def _publication_identity(result: object) -> FileIdentity:
    identity = getattr(result, "destination_identity", None)
    if identity is None:
        identity = getattr(result, "identity", None)
    if not isinstance(identity, FileIdentity):
        raise TypeError("publication returned no file identity")
    return identity


def _serialize_signing_journal(
    values: Mapping[str, str],
    pki_dir: str,
    active_intermediate: str,
) -> bytes:
    try:
        data = "".join(
            f"{field}={values[field]}\n" for field in CSR_SIGNING_JOURNAL_FIELDS
        ).encode("ascii")
        parse_signing_journal(
            data,
            pki_dir=pki_dir,
            active_intermediate_dir=active_intermediate,
        )
        return data
    except (KeyError, UnicodeEncodeError, CsrRecoveryError):
        _die("CSR signing recovery journal could not be serialized safely")


@dataclass(slots=True)
class _SigningControl:
    path: str
    pki_dir: str
    active_intermediate: str
    values: dict[str, str]
    identity: FileIdentity

    def recheck(self) -> None:
        try:
            with OpenedFile(
                self.path,
                policy=_JOURNAL_POLICY,
                expected_identity=self.identity,
            ):
                pass
        except FilesystemError:
            _die("CSR signing recovery journal identity changed")

    def write(self) -> SigningJournal:
        data = _serialize_signing_journal(
            self.values, self.pki_dir, self.active_intermediate
        )
        parent, name = _parent(self.path)
        try:
            try:
                result = atomic_write_bytes(
                    parent,
                    name,
                    data,
                    expected_destination=self.identity,
                )
            except (FilesystemError, PublicationError):
                _die("CSR signing recovery journal could not be rewritten safely")
            self.identity = _publication_identity(result)
        finally:
            parent.close()
        try:
            return parse_signing_journal(
                data,
                pki_dir=self.pki_dir,
                active_intermediate_dir=self.active_intermediate,
            )
        except CsrRecoveryError:
            raise AssertionError("serialized signing journal did not parse") from None


def _load_signing_journal(
    path: str,
    pki_dir: str,
    active_intermediate: str,
) -> tuple[_SigningControl, SigningJournal]:
    data = b""
    identity: FileIdentity | None = None
    try:
        with OpenedFile(path, policy=_JOURNAL_POLICY) as opened:
            data = opened.read(MAX_SIGNING_JOURNAL_BYTES)
            identity = opened.identity
        record = parse_signing_journal(
            data,
            pki_dir=pki_dir,
            active_intermediate_dir=active_intermediate,
        )
    except FilesystemError:
        _die("No safe CSR signing recovery journal exists")
    except CsrRecoveryError as error:
        if str(error) == (
            "CSR signing checkpoint evidence conflicts with its durable writer state"
        ):
            try:
                structure = parse_signing_journal_structure(data)
            except CsrRecoveryError:
                structure = None
            if structure is not None:
                transaction = structure["transaction"]
                expected_key = (
                    f"{pki_dir}/state/csr/transactions/{transaction}"
                    "/signing/private/intermediate-ca.key"
                )
                if (
                    _TRANSACTION.fullmatch(transaction) is not None
                    and structure["sensitive_key_path"] == expected_key
                    and structure["sensitive_key_identity"] == "none"
                    and os.path.lexists(expected_key)
                ):
                    _die(
                        "Journaled CSR signing key copy has no recorded identity"
                    )
        _die(str(error))
    assert identity is not None
    return (
        _SigningControl(
            path,
            pki_dir,
            active_intermediate,
            dict(record.items()),
            identity,
        ),
        record,
    )


def _load_active_signing_authority(pki_dir: str) -> tuple[str, str]:
    path = f"{pki_dir}/state/active-issuer"
    data = b""
    try:
        with OpenedFile(
            path,
            policy=FilePolicy(
                owner=os.geteuid(), mode=0o600, links=1, max_size=4096
            ),
        ) as opened:
            data = opened.read(4096)
    except FilesystemError:
        _die("Active issuer manifest is invalid")
    try:
        lines = data.decode("ascii").splitlines()
    except UnicodeDecodeError:
        _die("Active issuer manifest is invalid")
    if (
        len(lines) != 2
        or re.fullmatch(r"root=g[1-9][0-9]*", lines[0], re.ASCII) is None
        or re.fullmatch(
            r"intermediate=g[1-9][0-9]*-i[1-9][0-9]*",
            lines[1],
            re.ASCII,
        )
        is None
    ):
        _die("Active issuer manifest is invalid")
    root = lines[0].removeprefix("root=")
    intermediate = lines[1].removeprefix("intermediate=")
    if not intermediate.startswith(f"{root}-i"):
        _die("Active issuer manifest selects mismatched generations")
    root_dir = f"{pki_dir}/authorities/roots/{root}"
    intermediate_dir = f"{pki_dir}/authorities/intermediates/{intermediate}"
    try:
        with OpenedDirectory(root_dir, policy=_PRIVATE_DIRECTORY):
            pass
        with OpenedDirectory(intermediate_dir, policy=_PRIVATE_DIRECTORY):
            pass
    except FilesystemError:
        _die("Active authority generation is unsafe")
    return root_dir, intermediate_dir


def _require_compatible_signing_state(pki_dir: str) -> None:
    if detect_layout(pki_dir) != "generation":
        _die("CSR recovery requires complete generation-aware PKI state")
    finalization = f"{pki_dir}/state/csr/finalization-recovery-journal"
    marker = f"{pki_dir}/state/rollover/recovery-required"
    rollover = f"{pki_dir}/state/rollover/journal"
    if os.path.lexists(finalization):
        _die("CSR candidate finalization recovery must be completed first")
    if os.path.lexists(marker):
        _die("PKI rollover recovery must be completed first")
    if os.path.lexists(rollover):
        state = _read_control_state(rollover, "PKI recovery journal")
        if state.get("operation") == "rollover-prepare" or state.get("committed") != "true":
            _die("PKI rollover recovery must be completed first")


def _identity_or_absent(path: str, label: str) -> FileIdentity | object:
    try:
        return identity_at(path)
    except FilesystemError:
        _die(f"{label} could not be inspected safely")


def _optional_identity(path: str, label: str) -> FileIdentity | object:
    if not os.path.lexists(path):
        return ABSENT
    return _identity_or_absent(path, label)


def _read_expected_file(
    path: str,
    expected: FileIdentity | FileObjectState,
    digest: str,
    label: str,
    *,
    policy: FilePolicy = _PROTOCOL_FILE,
) -> tuple[bytes, FileIdentity]:
    data = b""
    identity: FileIdentity | None = None
    try:
        with OpenedFile(path, policy=policy, expected_identity=expected) as opened:
            data = opened.read(policy.max_size or _MAX_EVIDENCE_BYTES)
            identity = opened.identity
    except FilesystemError:
        _die(f"{label} identity changed")
    if hashlib.sha256(data).hexdigest() != digest:
        _die(f"{label} digest changed")
    assert identity is not None
    return data, identity


def _replay_request_content(journal: SigningJournal) -> bytes:
    return (
        "schema=1\n"
        f"request_id={journal['request_id']}\n"
        f"nonce={journal['nonce']}\n"
        f"operation={journal['operation_kind']}\n"
        f"service={journal['service']}\n"
        f"target={journal['target']}\n"
        f"request_sha256={journal['request_sha256']}\n"
        f"approval_sha256={journal['approval_sha256']}\n"
        "outcome=reserved\n"
    ).encode("ascii")


def _replay_nonce_content(journal: SigningJournal) -> bytes:
    return (
        "schema=1\n"
        f"nonce={journal['nonce']}\n"
        f"request_id={journal['request_id']}\n"
        f"request_sha256={journal['request_sha256']}\n"
        "outcome=reserved\n"
    ).encode("ascii")


def _ensure_replay_record(
    path: str,
    content: bytes,
    expected: object,
    label: str,
    checkpoint_name: str,
    control: _SigningControl,
    fault: FaultHook,
    pause: PauseHook,
) -> tuple[FileIdentity, str]:
    digest = hashlib.sha256(content).hexdigest()
    try:
        actual = identity_at(path)
    except FilesystemError:
        _die(f"{label} is unsafe")
    if actual is ABSENT:
        if expected is not IdentitySentinel.NONE:
            _die(f"{label} disappeared after its identity was journaled")
        _checkpoint(f"{checkpoint_name}-before-mutation", fault, pause)
        control.recheck()
        parent, name = _parent(path)
        try:
            try:
                result = atomic_write_bytes(parent, name, content)
            except (FilesystemError, PublicationError):
                _die(f"Cannot reserve {label}")
            actual = _publication_identity(result)
        finally:
            parent.close()
        _checkpoint(f"{checkpoint_name}-after-mutation", fault, pause)
    if (
        not isinstance(actual, FileIdentity)
        or actual.kind != "regular"
        or actual.uid != os.geteuid()
        or actual.permissions != 0o600
        or actual.links != 1
    ):
        _die(f"{label} is unsafe")
    expected_identity = None if expected is IdentitySentinel.NONE else expected
    assert expected_identity is None or isinstance(expected_identity, FileIdentity)
    data, identity = _read_expected_file(
        path,
        expected_identity or actual,
        digest,
        label,
    )
    if data != content:
        _die(f"{label} conflicts with the recovery journal")
    return identity, digest


def _ensure_signing_replay(
    record: SigningJournal,
    control: _SigningControl,
    fault: FaultHook,
    pause: PauseHook,
) -> SigningJournal:
    request_expected = record.identity("replay_request_identity")
    nonce_expected = record.identity("replay_nonce_identity")
    if (
        request_expected is IdentitySentinel.NONE
        or nonce_expected is IdentitySentinel.NONE
    ) and (
        record.phase is not SigningPhase.PLANNED
        or record.recovery_step is not SigningRecoveryStep.PLANNED
    ):
        _die("CSR replay evidence is missing outside replay reservation")
    request_identity, request_digest = _ensure_replay_record(
        record.path("replay_request_path") or "",
        _replay_request_content(record),
        request_expected,
        "CSR request replay record",
        "replay-request",
        control,
        fault,
        pause,
    )
    nonce_identity, nonce_digest = _ensure_replay_record(
        record.path("replay_nonce_path") or "",
        _replay_nonce_content(record),
        nonce_expected,
        "CSR nonce replay record",
        "replay-nonce",
        control,
        fault,
        pause,
    )
    if request_expected is IdentitySentinel.NONE:
        _checkpoint("replay-before-evidence", fault, pause)
        control.values["replay_request_identity"] = serialize_file_identity(
            request_identity
        )
        control.values["replay_request_sha256"] = request_digest
        control.values["replay_nonce_identity"] = serialize_file_identity(nonce_identity)
        control.values["replay_nonce_sha256"] = nonce_digest
        control.values["recovery_step"] = SigningRecoveryStep.REPLAY_RESERVED.value
        _checkpoint("replay-after-evidence", fault, pause)
        record = control.write()
        _checkpoint("replay-after-journal-rewrite", fault, pause)
    return record


@dataclass(frozen=True, slots=True)
class _RollbackEntry:
    key: str
    path: str
    pre: FileIdentity | IdentitySentinel
    post: FileIdentity | IdentitySentinel
    source: FileObjectState | IdentitySentinel
    backup_path: str
    backup: FileIdentity | IdentitySentinel


def _classify_uncommitted_database_entry(
    entry: _RollbackEntry,
) -> tuple[str, FileIdentity | None]:
    current = _identity_or_absent(entry.path, "CSR CA state")
    backup_actual = _identity_or_absent(entry.backup_path, "CSR CA rollback copy")
    if entry.pre is IdentitySentinel.ABSENT:
        if entry.backup is not IdentitySentinel.NONE or backup_actual is not ABSENT:
            _die(f"CSR CA rollback copy {entry.key} is inconsistent")
        if current is ABSENT:
            return "pre", None
        if isinstance(current, FileIdentity) and (
            _matches(current, entry.post) or _matches(current, entry.source)
        ):
            return "rollback", current
        _die(f"CSR recovery found non-journaled CA state: {entry.path}")

    assert isinstance(entry.pre, FileIdentity)
    if _matches(current, entry.pre):
        assert isinstance(current, FileIdentity)
        if backup_actual is not ABSENT and not _matches(backup_actual, entry.backup):
            _die(f"CSR CA rollback copy {entry.key} identity changed")
        return "pre", current
    if not isinstance(entry.backup, FileIdentity):
        _die(f"CSR CA rollback copy {entry.key} is incomplete")
    if backup_actual is ABSENT and _matches(current, entry.backup.state):
        assert isinstance(current, FileIdentity)
        return "restored", current
    if not _matches(backup_actual, entry.backup):
        _die(f"CSR CA rollback copy {entry.key} identity changed")
    if isinstance(current, FileIdentity) and (
        _matches(current, entry.post) or _matches(current, entry.source)
    ):
        return "rollback", current
    _die(f"CSR recovery found non-journaled CA state: {entry.path}")


def _preflight_uncommitted_database(record: SigningJournal) -> tuple[_RollbackEntry, ...]:
    if record.path("db_index_path") is None:
        return ()
    entries = []
    for key in CSR_DB_KEYS:
        path = record.path(f"db_{key}_path")
        backup_path = record.path(f"db_{key}_backup")
        assert path is not None and backup_path is not None
        pre = record.identity(f"db_{key}_pre_identity")
        post = record.identity(f"db_{key}_post_identity")
        source = record.identity(f"db_{key}_source_object")
        backup = record.identity(f"db_{key}_backup_identity")
        assert isinstance(pre, (FileIdentity, IdentitySentinel))
        assert isinstance(post, (FileIdentity, IdentitySentinel))
        assert isinstance(source, (FileObjectState, IdentitySentinel))
        assert isinstance(backup, (FileIdentity, IdentitySentinel))
        entry = _RollbackEntry(key, path, pre, post, source, backup_path, backup)
        _classify_uncommitted_database_entry(entry)
        entries.append(entry)
    return tuple(entries)


def _record_restored_database_identity(
    record: SigningJournal,
    control: _SigningControl,
    entry: _RollbackEntry,
    fault: FaultHook,
    pause: PauseHook,
) -> SigningJournal:
    _checkpoint(f"rollback-{entry.key}-before-evidence", fault, pause)
    control.recheck()
    state, current = _classify_uncommitted_database_entry(entry)
    if state != "restored" or current is None:
        if state == "pre":
            return record
        _die(f"CSR CA rollback restoration changed before evidence: {entry.path}")
    control.values[f"db_{entry.key}_pre_identity"] = serialize_file_identity(current)
    _checkpoint(f"rollback-{entry.key}-after-evidence", fault, pause)
    record = control.write()
    _checkpoint(f"rollback-{entry.key}-after-journal-rewrite", fault, pause)
    return record


def _rollback_database(
    record: SigningJournal,
    control: _SigningControl,
    entries: tuple[_RollbackEntry, ...],
    fault: FaultHook,
    pause: PauseHook,
) -> SigningJournal:
    by_key = {entry.key: entry for entry in entries}
    for key in reversed(CSR_DB_KEYS):
        if key not in by_key:
            continue
        entry = by_key[key]
        state, current = _classify_uncommitted_database_entry(entry)
        if state == "pre":
            continue
        if state == "restored":
            record = _record_restored_database_identity(
                record, control, entry, fault, pause
            )
            continue
        _checkpoint(f"rollback-{key}-before-mutation", fault, pause)
        control.recheck()
        state, current = _classify_uncommitted_database_entry(entry)
        if state == "pre":
            continue
        if state == "restored":
            record = _record_restored_database_identity(
                record, control, entry, fault, pause
            )
            continue
        assert state == "rollback" and isinstance(current, FileIdentity)
        if entry.pre is IdentitySentinel.ABSENT:
            parent, name = _parent(entry.path)
            try:
                try:
                    unlink_exact(parent, name, current)
                except (FilesystemError, PublicationError):
                    _die(f"Cannot remove partial CSR CA publication: {entry.path}")
            finally:
                parent.close()
        else:
            assert isinstance(entry.backup, FileIdentity)
            source_parent, source_name = _parent(entry.backup_path)
            destination_parent, destination_name = _parent(entry.path)
            try:
                try:
                    replace_exact(
                        source_parent,
                        source_name,
                        entry.backup,
                        destination_parent,
                        destination_name,
                        current,
                        pre_exchange_check=control.recheck,
                    )
                except (FilesystemError, PublicationError):
                    _die(f"Cannot restore CSR CA rollback copy: {entry.path}")
            finally:
                destination_parent.close()
                source_parent.close()
        _checkpoint(f"rollback-{key}-after-mutation", fault, pause)
        if entry.pre is not IdentitySentinel.ABSENT:
            record = _record_restored_database_identity(
                record, control, entry, fault, pause
            )
    return record


def _remove_sensitive_signing_key(
    record: SigningJournal,
    control: _SigningControl,
    fault: FaultHook,
    pause: PauseHook,
) -> None:
    path = record.path("sensitive_key_path")
    assert path is not None
    expected = record.identity("sensitive_key_identity")
    if expected is IdentitySentinel.NONE and not os.path.lexists(path):
        return
    current = _identity_or_absent(path, "Journaled CSR signing key copy")
    if expected is IdentitySentinel.NONE:
        if current is not ABSENT:
            _die("Journaled CSR signing key copy has no recorded identity")
        return
    if current is ABSENT:
        return
    if not isinstance(expected, FileIdentity) or current != expected:
        _die("Journaled CSR signing key copy identity changed")
    _checkpoint("sensitive-key-before-mutation", fault, pause)
    control.recheck()
    parent, name = _parent(path)
    try:
        try:
            unlink_exact(parent, name, expected)
        except (FilesystemError, PublicationError):
            _die("Cannot remove journaled CSR signing key copy")
    finally:
        parent.close()
    _checkpoint("sensitive-key-after-mutation", fault, pause)


def _terminal_content(record: SigningJournal, outcome: str) -> bytes:
    return (
        "schema=1\n"
        f"transaction={record['transaction']}\n"
        f"request_id={record['request_id']}\n"
        f"operation={record['operation_kind']}\n"
        f"service={record['service']}\n"
        f"outcome={outcome}\n"
        f"committed={'true' if record.committed else 'false'}\n"
    ).encode("ascii")


def _ensure_terminal(
    record: SigningJournal,
    control: _SigningControl,
    outcome: str,
    fault: FaultHook,
    pause: PauseHook,
) -> SigningJournal:
    transaction_path = record.path("transaction_dir")
    assert transaction_path is not None
    transaction_expected = record.identity("transaction_identity")
    transaction_actual = _identity_or_absent(transaction_path, "CSR transaction")
    if transaction_actual is ABSENT:
        if transaction_expected is not IdentitySentinel.NONE:
            _die("Journaled CSR transaction directory disappeared")
        parent, name = _parent(transaction_path)
        try:
            control.recheck()
            try:
                os.mkdir(name, 0o700, dir_fd=parent.fileno())
                os.fsync(parent.fileno())
                transaction_actual = parent.identity_at(name)
            except OSError:
                _die("Cannot create terminal CSR transaction directory")
        finally:
            parent.close()
        if not isinstance(transaction_actual, FileIdentity):
            raise AssertionError("created transaction directory is absent")
    if not isinstance(transaction_actual, FileIdentity) or transaction_actual.kind != "directory":
        _die("CSR transaction directory is unsafe")
    if transaction_expected is IdentitySentinel.NONE:
        control.values["transaction_identity"] = serialize_directory_identity(
            transaction_actual.directory
        )
    expected_directory = (
        transaction_actual.directory  # type: ignore[union-attr]
        if transaction_expected is IdentitySentinel.NONE
        else transaction_expected
    )
    assert isinstance(expected_directory, DirectoryIdentity)
    try:
        with OpenedDirectory(
            transaction_path,
            policy=_PRIVATE_DIRECTORY,
            expected_identity=expected_directory,
        ) as transaction:
            terminal = _terminal_content(record, outcome)
            if (
                transaction_expected is IdentitySentinel.NONE
                and _directory_entries(transaction, "CSR transaction directory")
                - {"terminal"}
            ):
                _die("CSR transaction directory has unexpected or unsafe entries")
            actual = transaction.identity_at("terminal")
            if actual is ABSENT:
                _checkpoint("terminal-before-mutation", fault, pause)
                control.recheck()
                try:
                    atomic_write_bytes(transaction, "terminal", terminal)
                except (FilesystemError, PublicationError):
                    _die("Cannot publish terminal CSR transaction record")
                _checkpoint("terminal-after-mutation", fault, pause)
            else:
                if not isinstance(actual, FileIdentity):
                    _die("Terminal CSR transaction record is unsafe")
                data, _identity = _read_expected_file(
                    f"{transaction_path}/terminal",
                    actual,
                    hashlib.sha256(terminal).hexdigest(),
                    "Terminal CSR transaction record",
                )
                if data != terminal:
                    _die("Terminal CSR transaction record conflicts with recovery")
    except FilesystemError:
        _die("CSR transaction directory identity changed")
    return record


def _recoverable_unowned_terminal_transaction(
    record: SigningJournal,
    transaction_path: str,
) -> bool:
    if record.committed or record.identity("transaction_identity") is not IdentitySentinel.NONE:
        return False
    try:
        with OpenedDirectory(transaction_path, policy=_PRIVATE_DIRECTORY) as transaction:
            if _directory_entries(transaction, "CSR transaction directory") - {"terminal"}:
                return False
            actual = transaction.identity_at("terminal")
            if actual is ABSENT:
                return True
            if not isinstance(actual, FileIdentity):
                return False
            expected = _terminal_content(record, "failed-pre-commit")
            data, _identity = _read_expected_file(
                f"{transaction_path}/terminal",
                actual,
                hashlib.sha256(expected).hexdigest(),
                "Terminal CSR transaction record",
            )
            return data == expected
    except FilesystemError:
        return False
    return False


def _preflight_sensitive_signing_key(record: SigningJournal) -> None:
    path = record.path("sensitive_key_path")
    assert path is not None
    expected = record.identity("sensitive_key_identity")
    actual = _optional_identity(path, "Journaled CSR signing key copy")
    if expected is IdentitySentinel.NONE:
        if actual is not ABSENT:
            _die("Journaled CSR signing key copy has no recorded identity")
        return
    if actual is not ABSENT and actual != expected:
        _die("Journaled CSR signing key copy identity changed")


def _preflight_signing_terminal(record: SigningJournal, outcome: str) -> None:
    transaction_path = record.path("transaction_dir")
    assert transaction_path is not None
    expected = record.identity("transaction_identity")
    actual = _identity_or_absent(transaction_path, "CSR transaction")
    if expected is IdentitySentinel.NONE:
        if actual is ABSENT:
            return
        if not _recoverable_unowned_terminal_transaction(record, transaction_path):
            _die("Unowned CSR signing transaction directory is not a recovery window")
        return
    if not isinstance(expected, DirectoryIdentity) or not _matches(actual, expected):
        _die("CSR transaction directory identity changed")
    terminal = f"{transaction_path}/terminal"
    terminal_actual = _identity_or_absent(terminal, "Terminal CSR transaction record")
    if terminal_actual is ABSENT:
        if record.phase is SigningPhase.TERMINAL:
            _die("Terminal CSR transaction record is missing")
        return
    if not isinstance(terminal_actual, FileIdentity):
        _die("Terminal CSR transaction record is unsafe")
    content = _terminal_content(record, outcome)
    data, _identity = _read_expected_file(
        terminal,
        terminal_actual,
        hashlib.sha256(content).hexdigest(),
        "Terminal CSR transaction record",
    )
    if data != content:
        _die("Terminal CSR transaction record conflicts with recovery")


def _preflight_database_sources(record: SigningJournal) -> None:
    if record.path("db_index_path") is None:
        return
    for key in CSR_DB_KEYS:
        path = record.path(f"db_{key}_source")
        assert path is not None
        expected = record.identity(f"db_{key}_source_identity")
        actual = _identity_or_absent(path, f"CSR CA staged source {key}")
        if expected is IdentitySentinel.NONE:
            if actual is ABSENT:
                continue
            if (
                record.recovery_step is SigningRecoveryStep.SIGNING_READY
                and isinstance(actual, FileIdentity)
            ):
                try:
                    with OpenedFile(
                        path,
                        policy=_PRIVATE_FILE,
                        expected_identity=actual,
                    ) as source:
                        source.recheck()
                except FilesystemError:
                    _die(f"CSR CA staged source {key} is unsafe")
                continue
            _die(f"CSR CA staged source {key} has no recorded identity")
        if actual == expected:
            continue
        destination = record.path(f"db_{key}_path")
        assert destination is not None
        destination_actual = _identity_or_absent(destination, "CSR CA state")
        backup = record.identity(f"db_{key}_backup_identity")
        consumed = actual is ABSENT and (
            any(
                _matches(destination_actual, record.identity(f"db_{key}_{field}"))
                for field in (
                    "source_object",
                    "post_identity",
                    "pre_identity",
                )
            )
            or (
                isinstance(backup, FileIdentity)
                and _matches(destination_actual, backup.state)
            )
            or (
                record.identity(f"db_{key}_pre_identity")
                is IdentitySentinel.ABSENT
                and destination_actual is ABSENT
            )
        )
        if not consumed:
            _die(f"CSR CA staged source {key} identity changed")


def _preflight_committed_database(record: SigningJournal) -> None:
    _verify_committed_database(record)
    _preflight_database_sources(record)
    for key in CSR_DB_KEYS:
        path = record.path(f"db_{key}_backup")
        assert path is not None
        expected = record.identity(f"db_{key}_backup_identity")
        actual = _identity_or_absent(path, f"CSR CA rollback copy {key}")
        if expected is IdentitySentinel.NONE:
            if actual is not ABSENT:
                _die(f"CSR CA rollback copy {key} has no recorded identity")
        elif actual != expected:
            _die(f"CSR CA rollback copy {key} identity changed")


def _finish_signing_journal(
    record: SigningJournal,
    control: _SigningControl,
    fault: FaultHook,
    pause: PauseHook,
) -> None:
    if record.phase is not SigningPhase.TERMINAL:
        _checkpoint("terminal-before-evidence", fault, pause)
        control.values["phase"] = SigningPhase.TERMINAL.value
        control.values["recovery_step"] = SigningRecoveryStep.JOURNAL_CLEANUP_PENDING.value
        control.values["sensitive_key_removed"] = "true"
        _checkpoint("terminal-after-evidence", fault, pause)
        record = control.write()
        _checkpoint("terminal-after-journal-rewrite", fault, pause)
    control.recheck()
    parent, name = _parent(control.path)
    try:
        _checkpoint("signing-journal-before-cleanup", fault, pause)
        try:
            unlink_exact(parent, name, control.identity)
        except (FilesystemError, PublicationError):
            _die("CSR signing journal changed before terminal cleanup")
    finally:
        parent.close()


def _verify_committed_database(record: SigningJournal) -> None:
    for key in CSR_DB_KEYS:
        path = record.path(f"db_{key}_path")
        expected = record.identity(f"db_{key}_post_identity")
        assert path is not None and isinstance(expected, FileIdentity)
        actual = _identity_or_absent(path, "Committed CSR CA state")
        if actual != expected:
            _die(f"Committed CSR CA state identity changed: {path}")


def _preflight_signing_publication_paths(
    record: SigningJournal,
    *,
    allow_unjournaled_empty_stage: bool,
) -> None:
    for kind in ("candidate", "response"):
        stage = record.path(f"{kind}_stage")
        destination = record.path(f"{kind}_destination")
        assert stage is not None and destination is not None
        stage_expected = record.identity(f"{kind}_stage_identity")
        destination_expected = record.identity(f"{kind}_destination_identity")
        stage_actual = _optional_identity(stage, f"CSR {kind} stage")
        destination_actual = _optional_identity(
            destination, f"CSR {kind} destination"
        )
        rename_step = (
            SigningRecoveryStep.RESPONSE_SIGNED
            if kind == "candidate"
            else SigningRecoveryStep.CANDIDATE_PUBLISHED
        )
        rename_window = (
            destination_expected is IdentitySentinel.NONE
            and isinstance(stage_expected, DirectoryIdentity)
            and stage_actual is ABSENT
            and _matches(destination_actual, stage_expected)
            and record.recovery_step is rename_step
        )
        published = (
            isinstance(stage_expected, DirectoryIdentity)
            and destination_expected == stage_expected
            and stage_actual is ABSENT
            and _matches(destination_actual, destination_expected)
        )
        unjournaled_empty_stage = False
        if (
            allow_unjournaled_empty_stage
            and stage_expected is IdentitySentinel.NONE
            and isinstance(stage_actual, FileIdentity)
        ):
            try:
                with OpenedDirectory(
                    stage,
                    policy=_PRIVATE_DIRECTORY,
                    expected_identity=stage_actual.directory,
                ) as directory:
                    unjournaled_empty_stage = not _directory_entries(
                        directory, f"CSR {kind} stage"
                    )
            except (FilesystemError, ValueError):
                unjournaled_empty_stage = False
        if not rename_window and not published:
            if stage_expected is IdentitySentinel.NONE:
                if stage_actual is not ABSENT and not unjournaled_empty_stage:
                    if isinstance(stage_actual, FileIdentity) and stage_actual.kind == "directory":
                        expected_names = {
                            "tls.crt",
                            "ca-chain.crt",
                            "fullchain.crt",
                            "response",
                            "response.sig",
                        }
                        if kind == "candidate":
                            expected_names.add("candidate")
                        names: frozenset[str] = frozenset()
                        try:
                            with OpenedDirectory(
                                stage,
                                policy=_PRIVATE_DIRECTORY,
                                expected_identity=stage_actual.directory,
                            ) as directory:
                                names = _directory_entries(
                                    directory, f"CSR {kind} artifact directory"
                                )
                        except FilesystemError:
                            _die(f"CSR {kind} artifact directory is unsafe")
                        if not names <= expected_names:
                            _die(
                                f"CSR {kind} artifact directory has unexpected or unsafe entries: {stage}"
                            )
                    _die(f"Unowned staged CSR {kind} artifact already exists")
            elif not _matches(stage_actual, stage_expected):
                if (
                    stage_actual is ABSENT
                    and destination_expected is not IdentitySentinel.NONE
                    and not _matches(destination_actual, destination_expected)
                ):
                    _die(f"Published CSR {kind} artifact identity changed")
                _die(f"Staged CSR {kind} artifact identity changed")
            if destination_expected is IdentitySentinel.NONE:
                if destination_actual is not ABSENT:
                    _die(f"Unowned CSR {kind} destination appeared")
            elif not _matches(destination_actual, destination_expected):
                _die(f"CSR {kind} destination identity changed")


_COMMITTED_SOURCE_FIELDS = (
    ("response_trust", "Journaled CSR response trust"),
    ("certificate", "Journaled issued certificate"),
    ("chain", "Journaled CSR CA chain"),
    ("fullchain", "Journaled CSR full chain"),
    ("response_manifest", "Journaled unsigned response"),
)


def _load_committed_sources(record: SigningJournal) -> dict[str, bytes]:
    sources = {}
    for prefix, label in _COMMITTED_SOURCE_FIELDS:
        path = record.path(f"{prefix}_path")
        expected = record.identity(f"{prefix}_identity")
        assert path is not None and isinstance(expected, FileIdentity)
        data, _identity = _read_expected_file(
            path,
            expected,
            record[f"{prefix}_sha256"],
            label,
        )
        sources[prefix] = data
    return sources


def _preflight_optional_signing_sources(record: SigningJournal) -> None:
    for prefix, label in _COMMITTED_SOURCE_FIELDS:
        path = record.path(f"{prefix}_path")
        expected = record.identity(f"{prefix}_identity")
        if expected is IdentitySentinel.NONE:
            if path is not None and _optional_identity(path, label) is not ABSENT:
                _die(f"{label} has no recorded identity")
            continue
        assert path is not None and isinstance(expected, FileIdentity)
        _read_expected_file(path, expected, record[f"{prefix}_sha256"], label)


def _run_ssh_keygen(
    argv: tuple[str, ...],
    environment: Mapping[str, str],
    *,
    input: bytes | None = None,
    pass_fds: tuple[int, ...] = (),
) -> ProcessResult:
    try:
        result = run_process(
            argv,
            env=environment,
            timeout=30.0,
            term_grace=1.0,
            stdout_limit=1024 * 1024,
            stderr_limit=1024 * 1024,
            input=input,
            pass_fds=pass_fds,
        )
    except ApplicationError:
        _die("OpenSSH signature operation failed")
    assert isinstance(result, ProcessResult)
    return result


def _allowed_response_key(trust: bytes, principal: str) -> str:
    try:
        lines = trust.decode("ascii").splitlines()
    except UnicodeDecodeError:
        _die("Journaled CSR response trust is invalid")
    if len(lines) != 1:
        _die("Journaled CSR response trust contains additional principals")
    fields = lines[0].split(" ")
    if (
        len(fields) != 3
        or fields[0] != principal
        or fields[1] != "ssh-ed25519"
        or re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", fields[2], re.ASCII) is None
    ):
        _die("Journaled CSR response trust is not a canonical pinned Ed25519 signer")
    return fields[2]


def _verify_response_signature(
    record: SigningJournal,
    environment: Mapping[str, str],
    manifest: bytes,
    signature_identity: FileIdentity,
    signature_digest: str,
    *,
    signature_policy: FilePolicy = _PROTOCOL_FILE,
) -> tuple[bytes, FileIdentity]:
    trust_path = record.path("response_trust_path")
    signature_path = record.path("response_signature_path")
    trust_expected = record.identity("response_trust_identity")
    assert trust_path is not None and signature_path is not None
    assert isinstance(trust_expected, FileIdentity)
    if not _matches(
        _identity_or_absent(signature_path, "Journaled CSR response signature"),
        signature_identity,
    ):
        _die("Journaled CSR response signature identity changed")
    try:
        with OpenedFile(
            trust_path,
            policy=_PROTOCOL_FILE,
            expected_identity=trust_expected,
        ) as trust:
            trust_bytes = trust.read(_PROTOCOL_FILE.max_size or 1024 * 1024)
            _allowed_response_key(trust_bytes, record["response_principal"])
            with OpenedFile(
                signature_path,
                policy=signature_policy,
                expected_identity=signature_identity,
            ) as signature:
                signature_bytes = signature.read(signature_policy.max_size or 1024 * 1024)
                if hashlib.sha256(signature_bytes).hexdigest() != signature_digest:
                    _die("Journaled CSR response signature digest changed")
                descriptors = (trust.fileno(), signature.fileno())
                result = _run_ssh_keygen(
                    (
                        "ssh-keygen",
                        "-Y",
                        "verify",
                        "-f",
                        f"/proc/self/fd/{trust.fileno()}",
                        "-I",
                        record["response_principal"],
                        "-n",
                        "platform-pki-csr-response-v1",
                        "-s",
                        f"/proc/self/fd/{signature.fileno()}",
                    ),
                    environment,
                    input=manifest,
                    pass_fds=descriptors,
                )
                if result.status:
                    _die("CSR response signature verification failed")
                trust.recheck()
                signature.recheck()
                return signature_bytes, signature.identity
    except FilesystemError:
        _die("CSR response signature or trust identity changed")
    raise AssertionError("unreachable")


def _preflight_response_signature(
    record: SigningJournal,
    environment: Mapping[str, str],
    manifest: bytes,
) -> bytes | None:
    path = record.path("response_signature_path")
    assert path is not None
    expected = record.identity("response_signature_identity")
    actual = _optional_identity(path, "CSR response signature")
    if expected is not IdentitySentinel.NONE:
        assert isinstance(expected, FileIdentity)
        data, _identity = _verify_response_signature(
            record,
            environment,
            manifest,
            expected,
            record["response_signature_sha256"],
        )
        return data
    if actual is ABSENT:
        return None
    owned = record.recovery_step is SigningRecoveryStep.RESPONSE_SIGNING
    allowed_modes = {0o600, 0o644} if owned else {0o600}
    if not isinstance(actual, FileIdentity) or actual.kind != "regular":
        _die("Uncheckpointed CSR response signature is unsafe")
    if actual.uid != os.geteuid() or actual.links != 1 or actual.permissions not in allowed_modes:
        _die("Uncheckpointed CSR response signature is unsafe")
    try:
        with OpenedFile(
            path,
            policy=FilePolicy(
                owner=os.geteuid(),
                mode=actual.permissions,
                links=1,
                max_size=1024 * 1024,
            ),
            expected_identity=actual,
        ) as opened:
            opened.read(1024 * 1024)
            opened.recheck()
    except FilesystemError:
        _die("Uncheckpointed CSR response signature identity changed")
    return None


def _remove_unowned_response_signature(
    record: SigningJournal,
    control: _SigningControl,
    expected: FileIdentity,
) -> None:
    path = record.path("response_signature_path")
    assert path is not None
    control.recheck()
    _load_committed_sources(record)
    parent, name = _parent(path)
    try:
        try:
            unlink_exact(parent, name, expected)
        except (FilesystemError, PublicationError):
            _die("Cannot remove uncheckpointed CSR response signature")
    finally:
        parent.close()


def _ensure_response_signature(
    record: SigningJournal,
    control: _SigningControl,
    response_key: str | None,
    environment: Mapping[str, str],
    manifest: bytes,
    fault: FaultHook,
    pause: PauseHook,
) -> tuple[SigningJournal, bytes]:
    signature_path = record.path("response_signature_path")
    assert signature_path is not None
    expected = record.identity("response_signature_identity")
    actual = _identity_or_absent(signature_path, "CSR response signature")
    if expected is not IdentitySentinel.NONE:
        assert isinstance(expected, FileIdentity)
        data, _identity = _verify_response_signature(
            record,
            environment,
            manifest,
            expected,
            record["response_signature_sha256"],
        )
        return record, data

    owned_window = record.recovery_step is SigningRecoveryStep.RESPONSE_SIGNING
    if actual is not ABSENT and not owned_window:
        if (
            not isinstance(actual, FileIdentity)
            or actual.kind != "regular"
            or actual.uid != os.geteuid()
            or actual.permissions != 0o600
            or actual.links != 1
        ):
            _die("Uncheckpointed CSR response signature is unsafe")
        _remove_unowned_response_signature(record, control, actual)
        actual = ABSENT

    if actual is ABSENT:
        if not response_key:
            _die(
                "CSR recovery requires --response-key to complete committed response publication"
            )
        key_path = os.path.abspath(os.path.expanduser(response_key))
        if not os.path.isabs(key_path):
            _die("Response signing key path is invalid")
        try:
            with OpenedFile(key_path, policy=_RESPONSE_KEY_FILE) as key:
                if key.identity.size == 0:
                    _die("Response signing key is empty")
                public = _run_ssh_keygen(
                    ("ssh-keygen", "-y", "-f", f"/proc/self/fd/{key.fileno()}"),
                    environment,
                    pass_fds=(key.fileno(),),
                )
                if public.status:
                    _die("Cannot derive response signing public key")
                fields = public.stdout.decode("ascii", errors="replace").strip().split()
                trust = _load_committed_sources(record)["response_trust"]
                expected_key = _allowed_response_key(
                    trust, record["response_principal"]
                )
                if len(fields) < 2 or fields[:2] != ["ssh-ed25519", expected_key]:
                    _die("Response signing key does not match the pinned response signer")
                key.recheck()
                if record.recovery_step is not SigningRecoveryStep.RESPONSE_SIGNING:
                    control.values["recovery_step"] = (
                        SigningRecoveryStep.RESPONSE_SIGNING.value
                    )
                    record = control.write()
                _checkpoint("response-signature-before-mutation", fault, pause)
                control.recheck()
                result = _run_ssh_keygen(
                    (
                        "ssh-keygen",
                        "-Y",
                        "sign",
                        "-f",
                        f"/proc/self/fd/{key.fileno()}",
                        "-n",
                        "platform-pki-csr-response-v1",
                        record.path("response_manifest_path") or "",
                    ),
                    environment,
                    pass_fds=(key.fileno(),),
                )
                if result.status:
                    _die("Response signing failed; recovery-required state is retained")
                key.recheck()
        except FilesystemError:
            _die("Response signing key changed during signing")
        _checkpoint("response-signature-after-mutation", fault, pause)
        actual = _identity_or_absent(signature_path, "CSR response signature")
    if not isinstance(actual, FileIdentity):
        _die("Response signing did not create a regular detached signature")
    if (
        actual.kind != "regular"
        or actual.uid != os.geteuid()
        or actual.permissions not in {0o600, 0o644}
        or actual.links != 1
    ):
        _die("Uncheckpointed CSR response signature is unsafe")
    adoption_policy = FilePolicy(
        owner=os.geteuid(),
        mode=actual.permissions,
        links=1,
        max_size=1024 * 1024,
    )
    adoption_data = b""
    adoption_identity: FileIdentity | None = None
    try:
        with OpenedFile(
            signature_path,
            policy=adoption_policy,
            expected_identity=actual,
        ) as opened:
            adoption_data = opened.read(1024 * 1024)
            adoption_identity = opened.identity
    except FilesystemError:
        _die("CSR response signature identity changed")
    assert adoption_identity is not None
    adoption_digest = hashlib.sha256(adoption_data).hexdigest()
    _verify_response_signature(
        record,
        environment,
        manifest,
        adoption_identity,
        adoption_digest,
        signature_policy=adoption_policy,
    )
    if actual.permissions != 0o600:
        descriptor = -1
        try:
            descriptor = os.open(
                signature_path,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            )
            if identity_from_stat(os.fstat(descriptor)) != actual:
                raise OSError
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
            actual = identity_from_stat(os.fstat(descriptor))
            if identity_at(signature_path) != actual:
                raise OSError
        except (OSError, FilesystemError):
            _die("CSR response signature identity changed")
        finally:
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
    data = b""
    identity: FileIdentity | None = None
    try:
        with OpenedFile(
            signature_path,
            policy=_PROTOCOL_FILE,
            expected_identity=actual,
        ) as opened:
            data = opened.read(_PROTOCOL_FILE.max_size or 1024 * 1024)
            identity = opened.identity
    except FilesystemError:
        _die("CSR response signature identity changed")
    assert identity is not None
    digest = hashlib.sha256(data).hexdigest()
    if data != adoption_data or digest != adoption_digest:
        _die("CSR response signature changed after authentication")
    _checkpoint("response-signature-before-evidence", fault, pause)
    control.recheck()
    sources = _load_committed_sources(record)
    if sources["response_manifest"] != manifest:
        _die("Journaled CSR response manifest changed during signature adoption")
    if not _matches(
        _identity_or_absent(signature_path, "CSR response signature"), identity
    ):
        _die("CSR response signature identity changed before evidence")
    control.values["response_signature_identity"] = serialize_file_identity(identity)
    control.values["response_signature_sha256"] = digest
    control.values["recovery_step"] = SigningRecoveryStep.RESPONSE_SIGNED.value
    _checkpoint("response-signature-after-evidence", fault, pause)
    record = control.write()
    _checkpoint("response-signature-after-journal-rewrite", fault, pause)
    return record, data


def _candidate_content(record: SigningJournal, root_id: str, intermediate_id: str) -> bytes:
    return (
        "schema=1\n"
        f"request_id={record['request_id']}\n"
        f"nonce={record['nonce']}\n"
        f"operation={record['operation_kind']}\n"
        f"service={record['service']}\n"
        f"target={record['target']}\n"
        "state=pending\n"
        f"request_sha256={record['request_sha256']}\n"
        f"approval_sha256={record['approval_sha256']}\n"
        f"inventory_sha256={record['inventory_sha256']}\n"
        f"csr_sha256={record['csr_sha256']}\n"
        f"csr_spki_sha256={record['csr_spki_sha256']}\n"
        f"certificate_sha256={record['certificate_sha256']}\n"
        f"chain_sha256={record['chain_sha256']}\n"
        f"issuer_root={root_id}\n"
        f"issuer_intermediate={intermediate_id}\n"
        f"serial={record.issued_serial}\n"
        f"response_sha256={record['response_manifest_sha256']}\n"
        f"response_signature_sha256={record['response_signature_sha256']}\n"
        f"created_epoch={record['created_epoch']}\n"
    ).encode("ascii")


def _artifact_members(
    record: SigningJournal,
    signature: bytes,
    root_id: str,
    intermediate_id: str,
    kind: str,
    sources: Mapping[str, bytes],
) -> tuple[tuple[str, bytes], ...]:
    members = [
        ("tls.crt", sources["certificate"]),
        ("ca-chain.crt", sources["chain"]),
        ("fullchain.crt", sources["fullchain"]),
        ("response", sources["response_manifest"]),
        ("response.sig", signature),
    ]
    if kind == "candidate":
        members.append(
            ("candidate", _candidate_content(record, root_id, intermediate_id))
        )
    return tuple(members)


def _preflight_artifact_contents(
    record: SigningJournal,
    kind: str,
    members: tuple[tuple[str, bytes], ...],
) -> None:
    expected_members = dict(members)
    for location in ("stage", "destination"):
        path = record.path(f"{kind}_{location}")
        assert path is not None
        actual = _optional_identity(path, f"CSR {kind} {location}")
        if actual is ABSENT:
            continue
        if not isinstance(actual, FileIdentity) or actual.kind != "directory":
            _die(f"CSR {kind} {location} is unsafe")
        try:
            with OpenedDirectory(
                path,
                policy=_PRIVATE_DIRECTORY,
                expected_identity=actual.directory,
            ) as directory:
                names = _directory_entries(directory, f"CSR {kind} {location}")
                if location == "destination":
                    valid_names = names == expected_members.keys()
                else:
                    valid_names = names <= expected_members.keys()
                if not valid_names:
                    _die(
                        f"CSR {kind} artifact directory has unexpected or unsafe entries: {path}"
                    )
                for name in names:
                    expected = expected_members[name]
                    data = b""
                    try:
                        with directory.open_file(name, policy=_PROTOCOL_FILE) as opened:
                            data = opened.read(_PROTOCOL_FILE.max_size or 1024 * 1024)
                    except FilesystemError:
                        _die(f"CSR {kind} {location} file is unsafe: {name}")
                    if data != expected:
                        if kind == "candidate" and location == "destination" and name == "candidate":
                            _die("Published CSR candidate record changed")
                        _die(f"CSR {kind} {location} file changed: {name}")
        except FilesystemError:
            _die(f"CSR {kind} {location} identity changed")


def _validate_artifact_tree(
    path: str,
    expected: DirectoryIdentity,
    members: tuple[tuple[str, bytes], ...],
    label: str,
) -> tuple[FileIdentity, TreeReadiness]:
    readiness: TreeReadiness | None = None
    parent, name = _parent(path)
    try:
        try:
            with parent.open_directory(
                name,
                policy=_PRIVATE_DIRECTORY,
                expected_identity=expected,
            ) as directory:
                if _directory_entries(directory, label) != {name for name, _ in members}:
                    _die(f"{label} has unexpected or unsafe entries")
                for member, expected_data in members:
                    data = b""
                    try:
                        with directory.open_file(member, policy=_PROTOCOL_FILE) as opened:
                            data = opened.read(_PROTOCOL_FILE.max_size or 1024 * 1024)
                    except FilesystemError:
                        _die(f"{label} is incomplete")
                    if data != expected_data:
                        _die(f"{label} digest changed: {member}")
                readiness = fsync_tree(directory, parent, name)
                return directory.identity, readiness
        except (FilesystemError, PublicationError):
            _die(f"{label} could not be durably validated")
    finally:
        parent.close()
    raise AssertionError("unreachable")


def _prepare_artifact_stage(
    record: SigningJournal,
    control: _SigningControl,
    kind: str,
    members: tuple[tuple[str, bytes], ...],
    fault: FaultHook,
    pause: PauseHook,
) -> tuple[SigningJournal, FileIdentity, TreeReadiness]:
    path = record.path(f"{kind}_stage")
    assert path is not None
    expected = record.identity(f"{kind}_stage_identity")
    actual = _identity_or_absent(path, f"Staged CSR {kind} artifact")
    if actual is ABSENT:
        if expected is not IdentitySentinel.NONE:
            _die(f"Staged CSR {kind} artifact disappeared after its identity was journaled")
        parent, name = _parent(path)
        try:
            _checkpoint(f"{kind}-stage-before-mutation", fault, pause)
            control.recheck()
            try:
                os.mkdir(name, 0o700, dir_fd=parent.fileno())
                os.fsync(parent.fileno())
                actual = parent.identity_at(name)
            except OSError:
                _die(f"Cannot create staged CSR {kind} artifact")
            _checkpoint(f"{kind}-stage-after-mutation", fault, pause)
        finally:
            parent.close()
    if not isinstance(actual, FileIdentity) or actual.kind != "directory":
        _die(f"Staged CSR {kind} artifact is unsafe")
    if expected is not IdentitySentinel.NONE and not _matches(actual, expected):
        _die(f"Staged CSR {kind} artifact identity changed")
    if expected is IdentitySentinel.NONE:
        _checkpoint(f"{kind}-stage-before-evidence", fault, pause)
        control.values[f"{kind}_stage_identity"] = (
            f"{actual.dev}:{actual.ino}:{actual.uid}:{actual.permissions:o}:directory"
        )
        _checkpoint(f"{kind}-stage-after-evidence", fault, pause)
        record = control.write()
        _checkpoint(f"{kind}-stage-after-journal-rewrite", fault, pause)
    identity: FileIdentity | None = None
    readiness: TreeReadiness | None = None
    try:
        with OpenedDirectory(
            path,
            policy=_PRIVATE_DIRECTORY,
            expected_identity=actual.directory,
        ) as directory:
            names = _directory_entries(directory, f"Staged CSR {kind} artifact")
            expected_names = {name for name, _ in members}
            if not names <= expected_names:
                _die(
                    f"Staged CSR {kind} artifact directory has unexpected or unsafe entries"
                )
            for name, content in members:
                present = directory.identity_at(name)
                if present is ABSENT:
                    _checkpoint(f"{kind}-{name}-before-mutation", fault, pause)
                    control.recheck()
                    try:
                        atomic_write_bytes(directory, name, content)
                    except (FilesystemError, PublicationError):
                        _die(f"Cannot stage CSR {kind} artifact file: {name}")
                    _checkpoint(f"{kind}-{name}-after-mutation", fault, pause)
                elif isinstance(present, FileIdentity):
                    try:
                        with directory.open_file(
                            name,
                            policy=_PROTOCOL_FILE,
                            expected_identity=present,
                        ) as opened:
                            if opened.read(_PROTOCOL_FILE.max_size or 1024 * 1024) != content:
                                _die(f"Staged CSR {kind} artifact file changed: {name}")
                    except FilesystemError:
                        _die(f"Staged CSR {kind} artifact file is unsafe: {name}")
                else:
                    _die(f"Staged CSR {kind} artifact file is unsafe: {name}")
            identity = directory.identity
    except FilesystemError:
        _die(f"Staged CSR {kind} artifact identity changed")
    assert identity is not None
    parent, name = _parent(path)
    try:
        with parent.open_directory(
            name, policy=_PRIVATE_DIRECTORY, expected_identity=identity.directory
        ) as directory:
            readiness = fsync_tree(directory, parent, name)
    finally:
        parent.close()
    assert readiness is not None
    return record, identity, readiness


def _publish_artifact(
    record: SigningJournal,
    control: _SigningControl,
    kind: str,
    members: tuple[tuple[str, bytes], ...],
    retained_sources: Mapping[str, bytes],
    fault: FaultHook,
    pause: PauseHook,
) -> SigningJournal:
    stage = record.path(f"{kind}_stage")
    destination = record.path(f"{kind}_destination")
    assert stage is not None and destination is not None
    stage_expected = record.identity(f"{kind}_stage_identity")
    destination_expected = record.identity(f"{kind}_destination_identity")
    stage_actual = _identity_or_absent(stage, f"Staged CSR {kind} artifact")
    destination_actual = _identity_or_absent(
        destination, f"Published CSR {kind} artifact"
    )
    if destination_actual is not ABSENT:
        expected = destination_expected
        if expected is IdentitySentinel.NONE:
            allowed = (
                SigningRecoveryStep.RESPONSE_SIGNED
                if kind == "candidate"
                else SigningRecoveryStep.CANDIDATE_PUBLISHED
            )
            if (
                record.recovery_step is not allowed
                or stage_expected is IdentitySentinel.NONE
                or stage_actual is not ABSENT
            ):
                _die(
                    f"Published CSR {kind} artifact has no identity outside the rename checkpoint window"
                )
            expected = stage_expected
        assert isinstance(expected, DirectoryIdentity)
        identity, _readiness = _validate_artifact_tree(
            destination,
            expected,
            members,
            f"Published CSR {kind} artifact directory",
        )
    else:
        if not isinstance(stage_expected, DirectoryIdentity):
            _die(f"Staged CSR {kind} artifact has no recorded identity")
        if not _matches(stage_actual, stage_expected):
            _die(f"Staged CSR {kind} artifact identity changed before publication")
        identity, readiness = _validate_artifact_tree(
            stage,
            stage_expected,
            members,
            f"Staged CSR {kind} artifact directory",
        )
        source_parent, source_name = _parent(stage)
        destination_parent, destination_name = _parent(destination)
        try:
            _checkpoint(f"{kind}-publish-before-mutation", fault, pause)
            control.recheck()
            _verify_committed_database(record)
            if _load_committed_sources(record) != retained_sources:
                _die("Journaled CSR source changed before publication")
            try:
                result = publish_no_clobber(
                    source_parent,
                    source_name,
                    identity,
                    destination_parent,
                    destination_name,
                    readiness=readiness,
                )
            except (FilesystemError, PublicationError):
                _die(f"Cannot publish CSR {kind} artifact")
            identity = _publication_identity(result)
            _checkpoint(f"{kind}-publish-after-mutation", fault, pause)
        finally:
            destination_parent.close()
            source_parent.close()
        _validate_artifact_tree(
            destination,
            identity.directory,
            members,
            f"Published CSR {kind} artifact directory",
        )
    if destination_expected is IdentitySentinel.NONE:
        _checkpoint(f"{kind}-publish-before-evidence", fault, pause)
        control.values[f"{kind}_destination_identity"] = control.values[
            f"{kind}_stage_identity"
        ]
        control.values["recovery_step"] = (
            SigningRecoveryStep.CANDIDATE_PUBLISHED.value
            if kind == "candidate"
            else SigningRecoveryStep.RESPONSE_PUBLISHED.value
        )
        _checkpoint(f"{kind}-publish-after-evidence", fault, pause)
        record = control.write()
        _checkpoint(f"{kind}-publish-after-journal-rewrite", fault, pause)
        _checkpoint(f"{kind}-published", fault, pause)
    return record


def _preflight_uncommitted_signing(
    record: SigningJournal,
) -> tuple[_RollbackEntry, ...]:
    entries = _preflight_uncommitted_database(record)
    _preflight_database_sources(record)
    _preflight_sensitive_signing_key(record)
    _preflight_signing_terminal(record, "failed-pre-commit")
    _preflight_optional_signing_sources(record)
    signature_path = record.path("response_signature_path")
    if signature_path is not None and _optional_identity(
        signature_path, "CSR response signature"
    ) is not ABSENT:
        _die("Uncommitted CSR recovery has an unexpected response signature")
    _preflight_signing_publication_paths(
        record,
        allow_unjournaled_empty_stage=False,
    )
    return entries


def _preflight_committed_signing(
    record: SigningJournal,
    root_id: str,
    intermediate_id: str,
    environment: Mapping[str, str],
) -> tuple[dict[str, bytes], bytes | None]:
    _preflight_committed_database(record)
    _preflight_sensitive_signing_key(record)
    _preflight_signing_terminal(record, "published")
    sources = _load_committed_sources(record)
    signature = _preflight_response_signature(
        record,
        environment,
        sources["response_manifest"],
    )
    _preflight_signing_publication_paths(
        record,
        allow_unjournaled_empty_stage=True,
    )
    if signature is None:
        for kind in ("candidate", "response"):
            for location in ("stage", "destination"):
                path = record.path(f"{kind}_{location}")
                assert path is not None
                if _optional_identity(path, f"CSR {kind} {location}") is not ABSENT:
                    _die(f"CSR {kind} {location} exists before response signing")
    else:
        for kind in ("candidate", "response"):
            members = _artifact_members(
                record,
                signature,
                root_id,
                intermediate_id,
                kind,
                sources,
            )
            _preflight_artifact_contents(record, kind, members)
    return sources, signature


def _recover_uncommitted_signing(
    record: SigningJournal,
    control: _SigningControl,
    stream: TextIO,
    fault: FaultHook,
    pause: PauseHook,
) -> None:
    entries = _preflight_uncommitted_signing(record)
    record = _rollback_database(record, control, entries, fault, pause)
    _remove_sensitive_signing_key(record, control, fault, pause)
    record = _ensure_terminal(
        record, control, "failed-pre-commit", fault, pause
    )
    _finish_signing_journal(record, control, fault, pause)
    print(
        "[OK] Terminalized uncommitted CSR request without reusing its identity: "
        f"{record['request_id']}",
        file=stream,
    )
    stream.flush()


def _recover_committed_signing(
    record: SigningJournal,
    control: _SigningControl,
    root_id: str,
    intermediate_id: str,
    response_key: str | None,
    environment: Mapping[str, str],
    stream: TextIO,
    fault: FaultHook,
    pause: PauseHook,
) -> None:
    sources, _existing_signature = _preflight_committed_signing(
        record,
        root_id,
        intermediate_id,
        environment,
    )
    manifest = sources["response_manifest"]
    record, signature = _ensure_response_signature(
        record,
        control,
        response_key,
        environment,
        manifest,
        fault,
        pause,
    )
    _verify_committed_database(record)
    sources = _load_committed_sources(record)
    _remove_sensitive_signing_key(record, control, fault, pause)
    artifacts = {
        kind: _artifact_members(
            record,
            signature,
            root_id,
            intermediate_id,
            kind,
            sources,
        )
        for kind in ("candidate", "response")
    }
    for kind, members in artifacts.items():
        destination = record.path(f"{kind}_destination")
        assert destination is not None
        if _identity_or_absent(destination, f"Published CSR {kind} artifact") is ABSENT:
            record, _identity, _readiness = _prepare_artifact_stage(
                record, control, kind, members, fault, pause
            )
        _verify_committed_database(record)
        current_sources = _load_committed_sources(record)
        if current_sources != sources:
            _die("Journaled CSR source changed during recovery")
    for kind, members in artifacts.items():
        record = _publish_artifact(
            record, control, kind, members, sources, fault, pause
        )
    record = _ensure_terminal(record, control, "published", fault, pause)
    _finish_signing_journal(record, control, fault, pause)
    print(
        f"[OK] Published host-local CSR response: {record.path('response_destination')}",
        file=stream,
    )
    print(
        f"[OK] Recorded pending host-local candidate: {record.path('candidate_destination')}",
        file=stream,
    )
    stream.flush()


def _recover_signing_locked(
    path: str,
    *,
    transaction: str,
    response_key: str | None,
    environment: Mapping[str, str],
    stream: TextIO,
    fault_hook: FaultHook,
    pause_hook: PauseHook,
) -> int:
    journal_path = f"{path}/state/csr/recovery-journal"

    _require_compatible_signing_state(path)
    root_dir, intermediate_dir = _load_active_signing_authority(path)
    root_id = os.path.basename(root_dir)
    intermediate_id = os.path.basename(intermediate_dir)
    control, record = _load_signing_journal(
        journal_path, path, intermediate_dir
    )
    if record["transaction"] != transaction:
        _die("CSR recovery transaction does not match the journal")
    transaction_path = record.path("transaction_dir")
    assert transaction_path is not None
    transaction_exists = (
        _identity_or_absent(transaction_path, "CSR recovery transaction directory")
        is not ABSENT
    )
    if not (
        transaction_exists
        and _recoverable_unowned_terminal_transaction(record, transaction_path)
    ):
        try:
            validate_signing_transaction_presence(
                record,
                transaction_exists=transaction_exists,
            )
        except CsrRecoveryError as error:
            if str(error) == "unowned CSR signing transaction directory appeared":
                _die("Unowned CSR recovery transaction directory appeared")
            _die(str(error))
    expected_transaction = record.identity("transaction_identity")
    if expected_transaction is not IdentitySentinel.NONE:
        assert isinstance(expected_transaction, DirectoryIdentity)
        try:
            with OpenedDirectory(
                transaction_path,
                policy=_PRIVATE_DIRECTORY,
                expected_identity=expected_transaction,
            ):
                pass
        except FilesystemError:
            _die("CSR recovery transaction directory identity changed")
    if record.committed:
        require_program("ssh-keygen", environment)
    control.recheck()
    _checkpoint("signing-journal-loaded", fault_hook, pause_hook)
    record = _ensure_signing_replay(
        record, control, fault_hook, pause_hook
    )
    if record.committed:
        _recover_committed_signing(
            record,
            control,
            root_id,
            intermediate_id,
            response_key,
            environment,
            stream,
            fault_hook,
            pause_hook,
        )
    else:
        _recover_uncommitted_signing(
            record, control, stream, fault_hook, pause_hook
        )
    return 0


def recover_signing(
    pki_dir: os.PathLike[str] | str,
    *,
    transaction: str,
    response_key: str | None = None,
    environment: Mapping[str, str] | None = None,
    output: TextIO | None = None,
    fault_hook: FaultHook = DEFAULT_FAULT_HOOK,
    pause_hook: PauseHook = DEFAULT_PAUSE_HOOK,
) -> int:
    """Recover one exact final-Bash CSR signing journal without public dispatch."""

    path = os.fspath(pki_dir)
    if not isinstance(path, str):
        raise TypeError("pki_dir must be a text path")
    if not os.path.isabs(path) or os.path.normpath(path) != path:
        raise ValueError("pki_dir must be an absolute normalized path")
    if not isinstance(transaction, str) or not transaction:
        raise TypeError("transaction must be nonempty text")
    if response_key is not None and not isinstance(response_key, str):
        raise TypeError("response_key must be text or None")
    if not callable(fault_hook) or not callable(pause_hook):
        raise TypeError("recovery hooks must be callable")
    environment = os.environ if environment is None else environment
    stream = sys.stdout if output is None else output
    require_pki_directory(path)
    prepare_control_state(path)
    with acquire_operational_locks(path, "inventory"):
        return _recover_signing_locked(
            path,
            transaction=transaction,
            response_key=response_key,
            environment=environment,
            stream=stream,
            fault_hook=fault_hook,
            pause_hook=pause_hook,
        )


def _journal_presence(pki_dir: str) -> tuple[bool, bool]:
    return (
        os.path.lexists(f"{pki_dir}/state/csr/recovery-journal"),
        os.path.lexists(f"{pki_dir}/state/csr/finalization-recovery-journal"),
    )


def recover_csr(
    arguments: ParseResult,
    *,
    environment: Mapping[str, str] | None = None,
) -> int:
    """Dispatch public CSR recovery without changing protocols after confirmation."""

    if not isinstance(arguments, ParseResult):
        raise TypeError("arguments must be a ParseResult")
    environment = os.environ if environment is None else environment
    transaction = arguments.values.get("--transaction")
    response_key = arguments.values.get("--response-key")
    if transaction is not None and (
        not isinstance(transaction, str) or _TRANSACTION.fullmatch(transaction) is None
    ):
        _die("CSR recovery transaction ID is invalid")
    if response_key is not None and not isinstance(response_key, str):
        raise TypeError("response key must be text or None")

    paths = resolve_paths(arguments.values, environment)
    require_pki_directory(paths.pki_dir)
    selected = _journal_presence(paths.pki_dir)
    if selected == (True, True):
        _die("CSR recovery journal state is ambiguous")
    if selected == (False, False):
        _die("No CSR recovery journal exists")
    finalization = selected[1]
    if finalization:
        if response_key is not None:
            _die("--response-key is not accepted for candidate finalization recovery")
        description = "candidate finalization"
        profile = "export"
    else:
        if transaction is None:
            _die("--transaction is required for CSR signing recovery")
        description = transaction
        profile = "inventory"

    if "--yes" not in arguments.provided:
        if not sys.stdin.isatty():
            _die("CSR recovery requires a TTY or --yes")
        print(
            f"Type recover {description} to continue: ",
            file=sys.stderr,
            end="",
            flush=True,
        )
        confirmation = sys.stdin.readline().rstrip("\n")
        if confirmation != f"recover {description}":
            _die("CSR recovery confirmation did not match")

    prepare_control_state(paths.pki_dir)
    with acquire_operational_locks(paths.pki_dir, profile):
        if _journal_presence(paths.pki_dir) != selected:
            _die("CSR recovery journal state changed after confirmation")
        if finalization:
            fault, pause = recovery_hooks(environment)
            return _recover_finalization_locked(
                paths.pki_dir,
                transaction=transaction,
                stream=sys.stdout,
                fault_hook=fault,
                pause_hook=pause,
            )
        assert transaction is not None
        fault, pause = signing_recovery_hooks(environment)
        return _recover_signing_locked(
            paths.pki_dir,
            transaction=transaction,
            response_key=response_key,
            environment=environment,
            stream=sys.stdout,
            fault_hook=fault,
            pause_hook=pause,
        )


def recovery_hooks(environment: Mapping[str, str]) -> tuple[FaultHook, PauseHook]:
    """Build the non-public finalization-recovery test hooks."""

    crash_at = environment.get("PLATFORM_PKI_CSR_RECOVER_CRASH_AT")
    if not crash_at:
        crash_at = environment.get("PLATFORM_PKI_CANDIDATE_CRASH_AT")
    return (
        FaultHook(crash_at=crash_at),
        PauseHook(
            pause_at=environment.get("PLATFORM_PKI_CSR_RECOVER_PAUSE_AT"),
            marker=environment.get("PLATFORM_PKI_CSR_RECOVER_PAUSE_MARKER"),
            release=environment.get("PLATFORM_PKI_CSR_RECOVER_PAUSE_RELEASE"),
        ),
    )


def signing_recovery_hooks(
    environment: Mapping[str, str],
) -> tuple[FaultHook, PauseHook]:
    """Build the non-public signing-recovery test hooks."""

    return (
        FaultHook(crash_at=environment.get("PLATFORM_PKI_CSR_PYTHON_RECOVER_CRASH_AT")),
        PauseHook(
            pause_at=environment.get("PLATFORM_PKI_CSR_PYTHON_RECOVER_PAUSE_AT"),
            marker=environment.get("PLATFORM_PKI_CSR_PYTHON_RECOVER_PAUSE_MARKER"),
            release=environment.get("PLATFORM_PKI_CSR_PYTHON_RECOVER_PAUSE_RELEASE"),
        ),
    )
