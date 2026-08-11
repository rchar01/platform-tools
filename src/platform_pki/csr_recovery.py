"""Pure structural and semantic models for final-Bash CSR recovery journals."""

from __future__ import annotations

import os
import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from enum import Enum
from typing import TypeAlias

from .filesystem import DirectoryIdentity, FileIdentity, FileObjectState
from .persisted_identity import (
    IdentitySentinel,
    PersistedIdentityError,
    parse_directory_identity,
    parse_file_identity,
    parse_file_object_state,
)


def _fields(value: str) -> tuple[str, ...]:
    return tuple(value.split())


CSR_DB_KEYS = (
    "index",
    "index_attr",
    "serial",
    "index_old",
    "index_attr_old",
    "serial_old",
    "newcert",
)
CSR_DB_PATHS = (
    ("index", "index.txt"),
    ("index_attr", "index.txt.attr"),
    ("serial", "serial"),
    ("index_old", "index.txt.old"),
    ("index_attr_old", "index.txt.attr.old"),
    ("serial_old", "serial.old"),
    ("newcert", "newcerts/{serial}.pem"),
)
CSR_DB_SUFFIXES = (
    "path",
    "pre_identity",
    "source",
    "source_identity",
    "source_object",
    "post_identity",
    "backup",
    "backup_identity",
)
CSR_SIGNING_FIXED_FIELDS = _fields("""
schema operation transaction phase committed recovery_step request_id nonce
operation_kind service target requester_principal approver_principal
response_principal request_sha256 approval_sha256 inventory_sha256 csr_sha256
csr_spki_sha256 current_cert_sha256 created_epoch transaction_dir
transaction_identity response_trust_path response_trust_identity
response_trust_sha256 sensitive_key_path sensitive_key_identity
sensitive_key_removed certificate_path certificate_identity certificate_sha256
chain_path chain_identity chain_sha256 fullchain_path fullchain_identity
fullchain_sha256 response_manifest_path response_manifest_identity
response_manifest_sha256 response_signature_path response_signature_identity
response_signature_sha256 candidate_stage candidate_stage_identity
candidate_destination candidate_destination_identity response_stage
response_stage_identity response_destination response_destination_identity
replay_request_path replay_request_identity replay_request_sha256
replay_nonce_path replay_nonce_identity replay_nonce_sha256
""")
CSR_SIGNING_JOURNAL_FIELDS = CSR_SIGNING_FIXED_FIELDS + tuple(
    f"db_{key}_{suffix}" for key in CSR_DB_KEYS for suffix in CSR_DB_SUFFIXES
)
# Compatibility names used by the migration inventory.
CSR_JOURNAL_FIELDS = CSR_SIGNING_JOURNAL_FIELDS

CANDIDATE_SOURCE_PATHS = (
    ("candidate_candidate", "candidate", "candidate"),
    ("candidate_tls_crt", "candidate", "tls.crt"),
    ("candidate_ca_chain_crt", "candidate", "ca-chain.crt"),
    ("candidate_fullchain_crt", "candidate", "fullchain.crt"),
    ("candidate_response", "candidate", "response"),
    ("candidate_response_sig", "candidate", "response.sig"),
    ("response_tls_crt", "response", "tls.crt"),
    ("response_ca_chain_crt", "response", "ca-chain.crt"),
    ("response_fullchain_crt", "response", "fullchain.crt"),
    ("response_response", "response", "response"),
    ("response_response_sig", "response", "response.sig"),
    ("artifact_artifact", "artifact", "artifact"),
    ("artifact_tls_crt", "artifact", "tls.crt"),
    ("artifact_ca_chain_crt", "artifact", "ca-chain.crt"),
    ("artifact_fullchain_crt", "artifact", "fullchain.crt"),
    ("artifact_response", "artifact", "response"),
    ("artifact_response_sig", "artifact", "response.sig"),
)
CANDIDATE_SOURCE_KEYS = tuple(key for key, _root, _name in CANDIDATE_SOURCE_PATHS)
CANDIDATE_FINALIZATION_FIXED_FIELDS = _fields("""
schema operation service request_id phase outcome_stage outcome_stage_identity
outcome_destination outcome_destination_identity active_stage
active_stage_identity active_destination active_pre_identity active_mode
active_destination_identity active_pre_sha256 candidate_dir candidate_dir_identity
response_dir response_dir_identity transaction_dir transaction_dir_identity
response_trust_path response_trust_identity response_trust_sha256
candidate_path candidate_identity candidate_sha256 artifact_dir
artifact_dir_identity artifact_path artifact_identity artifact_sha256
response_path response_identity response_sha256 response_signature_path
response_signature_identity response_signature_sha256 deployment_sha256
deployment_signature_sha256 deployers_sha256 decision_sha256 active_sha256
outcome_deployment_identity outcome_deployment_signature_identity
outcome_deployers_identity outcome_decision_identity
""")
CANDIDATE_FINALIZATION_JOURNAL_FIELDS = CANDIDATE_FINALIZATION_FIXED_FIELDS + tuple(
    f"source_{key}_{suffix}"
    for key in CANDIDATE_SOURCE_KEYS
    for suffix in ("identity", "sha256")
)
CANDIDATE_JOURNAL_FIELDS = CANDIDATE_FINALIZATION_JOURNAL_FIELDS


class CsrRecoveryError(ValueError):
    """A CSR recovery journal violates the frozen final-Bash contract."""


class CsrOperationKind(Enum):
    ISSUE = "issue"
    MIGRATE = "migrate"
    RENEW = "renew"


class SigningPhase(Enum):
    PLANNED = "planned"
    CA_COMMITTED = "ca-committed"
    TERMINAL = "terminal"


class SigningRecoveryStep(Enum):
    PLANNED = "planned"
    REPLAY_RESERVED = "replay-reserved"
    TRANSACTION_STAGED = "transaction-staged"
    SIGNING_READY = "signing-ready"
    SIGNING_COMPLETE = "signing-complete"
    SENSITIVE_KEY_REMOVED = "sensitive-key-removed"
    CA_INDEX_PUBLISHED = "ca-index-published"
    CA_INDEX_ATTR_PUBLISHED = "ca-index_attr-published"
    CA_SERIAL_PUBLISHED = "ca-serial-published"
    CA_INDEX_OLD_PUBLISHED = "ca-index_old-published"
    CA_INDEX_ATTR_OLD_PUBLISHED = "ca-index_attr_old-published"
    CA_SERIAL_OLD_PUBLISHED = "ca-serial_old-published"
    CA_NEWCERT_PUBLISHED = "ca-newcert-published"
    CA_COMMITTED = "ca-committed"
    RESPONSE_SIGNED = "response-signed"
    CANDIDATE_PUBLISHED = "candidate-published"
    RESPONSE_PUBLISHED = "response-published"
    JOURNAL_CLEANUP_PENDING = "journal-cleanup-pending"


SIGNING_PLANNED_STEPS = (
    SigningRecoveryStep.PLANNED,
    SigningRecoveryStep.REPLAY_RESERVED,
    SigningRecoveryStep.TRANSACTION_STAGED,
    SigningRecoveryStep.SIGNING_READY,
    SigningRecoveryStep.SIGNING_COMPLETE,
    SigningRecoveryStep.SENSITIVE_KEY_REMOVED,
    SigningRecoveryStep.CA_INDEX_PUBLISHED,
    SigningRecoveryStep.CA_INDEX_ATTR_PUBLISHED,
    SigningRecoveryStep.CA_SERIAL_PUBLISHED,
    SigningRecoveryStep.CA_INDEX_OLD_PUBLISHED,
    SigningRecoveryStep.CA_INDEX_ATTR_OLD_PUBLISHED,
    SigningRecoveryStep.CA_SERIAL_OLD_PUBLISHED,
    SigningRecoveryStep.CA_NEWCERT_PUBLISHED,
)
SIGNING_COMMITTED_STEPS = (
    SigningRecoveryStep.CA_COMMITTED,
    SigningRecoveryStep.RESPONSE_SIGNED,
    SigningRecoveryStep.CANDIDATE_PUBLISHED,
    SigningRecoveryStep.RESPONSE_PUBLISHED,
)
SIGNING_POST_STEPS = (
    SigningRecoveryStep.CA_INDEX_PUBLISHED,
    SigningRecoveryStep.CA_INDEX_ATTR_PUBLISHED,
    SigningRecoveryStep.CA_SERIAL_PUBLISHED,
    SigningRecoveryStep.CA_INDEX_OLD_PUBLISHED,
    SigningRecoveryStep.CA_INDEX_ATTR_OLD_PUBLISHED,
    SigningRecoveryStep.CA_SERIAL_OLD_PUBLISHED,
    SigningRecoveryStep.CA_NEWCERT_PUBLISHED,
)


class FinalizationPhase(Enum):
    PLANNED = "planned"
    OUTCOME_PUBLISHED = "outcome-published"
    ACTIVE_PUBLISHED = "active-published"


class ActivePublicationMode(Enum):
    CREATE = "create"
    EXCHANGE = "exchange"


ParsedIdentity: TypeAlias = (
    DirectoryIdentity | FileIdentity | FileObjectState | IdentitySentinel
)


@dataclass(frozen=True, slots=True)
class CsrJournalRecord(Mapping[str, str]):
    """An immutable ordered record retaining its original newline form."""

    pairs: tuple[tuple[str, str], ...]
    final_newline: bool

    def __getitem__(self, key: str) -> str:
        for field, value in self.pairs:
            if field == key:
                return value
        raise KeyError(key)

    def __iter__(self) -> Iterator[str]:
        return (field for field, _value in self.pairs)

    def __len__(self) -> int:
        return len(self.pairs)

    @property
    def fields(self) -> tuple[str, ...]:
        return tuple(self)


@dataclass(frozen=True, slots=True)
class SigningJournal(Mapping[str, str]):
    record: CsrJournalRecord
    pki_dir: str
    operation_kind: CsrOperationKind
    phase: SigningPhase
    recovery_step: SigningRecoveryStep
    committed: bool
    sensitive_key_removed: bool | None
    created_epoch: int
    issued_serial: str | None
    journal_intermediate_dir: str | None
    identities: tuple[tuple[str, ParsedIdentity], ...]
    paths: tuple[tuple[str, str | None], ...]

    def __getitem__(self, key: str) -> str:
        return self.record[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.record)

    def __len__(self) -> int:
        return len(self.record)

    def identity(self, field: str) -> ParsedIdentity:
        return dict(self.identities)[field]

    def path(self, field: str) -> str | None:
        return dict(self.paths)[field]


@dataclass(frozen=True, slots=True)
class FinalizationJournal(Mapping[str, str]):
    record: CsrJournalRecord
    pki_dir: str
    phase: FinalizationPhase
    active_mode: ActivePublicationMode
    identities: tuple[tuple[str, ParsedIdentity], ...]
    paths: tuple[tuple[str, str], ...]
    source_paths: tuple[tuple[str, str], ...]

    def __getitem__(self, key: str) -> str:
        return self.record[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.record)

    def __len__(self) -> int:
        return len(self.record)

    def identity(self, field: str) -> ParsedIdentity:
        return dict(self.identities)[field]

    def path(self, field: str) -> str:
        return dict(self.paths)[field]

    def source_path(self, key: str) -> str:
        return dict(self.source_paths)[key]


_KEY = re.compile(rb"[a-z0-9_]+", re.ASCII)
_REQUEST_ID = re.compile(r"[0-9a-f]{32}", re.ASCII)
_NONCE = re.compile(r"[0-9a-f]{64}", re.ASCII)
_DIGEST = re.compile(r"[0-9a-f]{64}", re.ASCII)
_SERVICE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*", re.ASCII)
_PRINCIPAL = re.compile(r"[a-z0-9][a-z0-9.-]*", re.ASCII)
_EPOCH = re.compile(r"0|[1-9][0-9]*", re.ASCII)
_SERIAL = re.compile(r"(?:[0-9A-F]{2})+", re.ASCII)
_STAGE_SUFFIX = re.compile(r"[A-Za-z0-9]{6}", re.ASCII)


def _parse_record(
    data: bytes,
    fields: tuple[str, ...],
    *,
    allow_empty: bool,
    require_final_newline: bool,
) -> CsrJournalRecord:
    if not isinstance(data, bytes):
        raise TypeError("CSR recovery journal input must be bytes")
    final_newline = data.endswith(b"\n")
    if require_final_newline and not final_newline:
        raise CsrRecoveryError("CSR recovery journal must end with one newline")
    if data.endswith(b"\n\n"):
        raise CsrRecoveryError("CSR recovery journal contains a blank extra record")
    body = data[:-1] if final_newline else data
    lines = body.split(b"\n") if body else ()
    if len(lines) < len(fields):
        raise CsrRecoveryError("CSR recovery journal is missing a required field")
    if len(lines) > len(fields):
        raise CsrRecoveryError("CSR recovery journal contains an extra field")

    pairs: list[tuple[str, str]] = []
    seen: set[bytes] = set()
    for line in lines:
        if b"=" not in line:
            raise CsrRecoveryError("CSR recovery journal contains a malformed field")
        key, value = line.split(b"=", 1)
        if _KEY.fullmatch(key) is None:
            raise CsrRecoveryError("CSR recovery journal contains an invalid field key")
        if key in seen:
            raise CsrRecoveryError("CSR recovery journal contains a duplicate field")
        seen.add(key)
        if not value and not allow_empty:
            raise CsrRecoveryError("CSR recovery journal contains an empty value")
        if any(byte < 0x20 or byte > 0x7E for byte in value):
            raise CsrRecoveryError("CSR recovery journal contains a non-ASCII value")
        pairs.append((key.decode("ascii"), value.decode("ascii")))

    actual = tuple(key for key, _value in pairs)
    if actual != fields:
        expected_set = set(fields)
        actual_set = set(actual)
        if actual_set - expected_set:
            raise CsrRecoveryError("CSR recovery journal contains an unexpected field")
        if expected_set - actual_set:
            raise CsrRecoveryError("CSR recovery journal is missing a required field")
        raise CsrRecoveryError("CSR recovery journal fields are reordered")
    return CsrJournalRecord(tuple(pairs), final_newline)


def parse_signing_journal_structure(data: bytes) -> CsrJournalRecord:
    """Parse the exact 114-field writer order without interpreting values."""

    record = _parse_record(
        data,
        CSR_SIGNING_JOURNAL_FIELDS,
        allow_empty=True,
        require_final_newline=False,
    )
    if record["schema"] != "1" or record["operation"] != "csr-sign":
        raise CsrRecoveryError("CSR signing journal schema or operation is unsupported")
    return record


def parse_finalization_journal_structure(data: bytes) -> CsrJournalRecord:
    """Parse the exact canonical 82-field finalization writer record."""

    record = _parse_record(
        data,
        CANDIDATE_FINALIZATION_JOURNAL_FIELDS,
        allow_empty=False,
        require_final_newline=True,
    )
    if record["schema"] != "1" or record["operation"] != "csr-finalize":
        raise CsrRecoveryError(
            "CSR finalization journal schema or operation is unsupported"
        )
    return record


def _canonical_pki_dir(path: os.PathLike[str] | str) -> str:
    value = os.fspath(path)
    if isinstance(value, bytes):
        raise TypeError("pki_dir must be a text path")
    if (
        not value
        or not os.path.isabs(value)
        or os.path.normpath(value) != value
        or "\0" in value
    ):
        raise CsrRecoveryError("pki_dir must be a canonical absolute path")
    return value


def _expect_pattern(value: str, pattern: re.Pattern[str], field: str) -> str:
    if pattern.fullmatch(value) is None:
        raise CsrRecoveryError(f"CSR recovery field {field} is invalid")
    return value


def _enum(enum_type, value: str, field: str):
    try:
        return enum_type(value)
    except ValueError:
        raise CsrRecoveryError(f"CSR recovery field {field} is invalid") from None


def _boolean(value: str, field: str) -> bool:
    if value not in {"false", "true"}:
        raise CsrRecoveryError(f"CSR recovery field {field} is not boolean")
    return value == "true"


def _digest(value: str, field: str, *, allow_none: bool = False) -> None:
    if allow_none and value == "none":
        return
    _expect_pattern(value, _DIGEST, field)


def _identity(
    value: str,
    field: str,
    kind: str,
    *,
    sentinels: frozenset[IdentitySentinel] = frozenset(),
) -> ParsedIdentity:
    try:
        if kind == "directory":
            return parse_directory_identity(value, allowed_sentinels=sentinels)
        if kind == "file":
            identity = parse_file_identity(value, allowed_sentinels=sentinels)
            if not isinstance(identity, IdentitySentinel) and identity.kind != "regular":
                raise PersistedIdentityError("persisted file identity is not regular")
            return identity
        if kind == "object":
            identity = parse_file_object_state(value, allowed_sentinels=sentinels)
            if not isinstance(identity, IdentitySentinel) and identity.kind != "regular":
                raise PersistedIdentityError("persisted file object state is not regular")
            return identity
    except PersistedIdentityError as error:
        raise CsrRecoveryError(
            f"CSR recovery identity {field} is invalid: {error}"
        ) from None
    raise AssertionError(f"unsupported CSR recovery identity kind: {kind}")


def _expect_path(value: str, expected: str, field: str) -> str:
    if (
        not os.path.isabs(value)
        or os.path.normpath(value) != value
        or value != expected
    ):
        raise CsrRecoveryError(f"CSR recovery path {field} is outside its contract")
    return value


def _optional_exact_path(value: str, expected: str, field: str) -> str | None:
    if value == "none":
        return None
    return _expect_path(value, expected, field)


def _optional_identity(
    record: CsrJournalRecord,
    identities: dict[str, ParsedIdentity],
    field: str,
    kind: str,
) -> None:
    identities[field] = _identity(
        record[field],
        field,
        kind,
        sentinels=frozenset((IdentitySentinel.NONE,)),
    )


def _optional_digest_identity_pair(
    record: CsrJournalRecord,
    identities: dict[str, ParsedIdentity],
    identity_field: str,
    digest_field: str,
    kind: str = "file",
) -> None:
    _optional_identity(record, identities, identity_field, kind)
    _digest(record[digest_field], digest_field, allow_none=True)
    if (record[identity_field] == "none") != (record[digest_field] == "none"):
        raise CsrRecoveryError(
            f"CSR recovery evidence {identity_field} is only partially recorded"
        )


def _validate_signing_checkpoint_evidence(
    record: CsrJournalRecord,
    phase: SigningPhase,
    committed: bool,
    recovery_step: SigningRecoveryStep,
    sensitive_removed: bool | None,
) -> None:
    def present(field: str) -> bool:
        return record[field] != "none"

    def uniform(fields: tuple[str, ...], label: str) -> bool:
        states = {present(field) for field in fields}
        if len(states) != 1:
            raise CsrRecoveryError(f"CSR signing {label} evidence is incomplete")
        return states.pop()

    if phase is not SigningPhase.TERMINAL and recovery_step not in {
        SigningRecoveryStep.PLANNED,
        SigningRecoveryStep.REPLAY_RESERVED,
        SigningRecoveryStep.TRANSACTION_STAGED,
    } and not present("sensitive_key_identity"):
        raise CsrRecoveryError(
            "Journaled CSR signing key copy has no recorded identity"
        )

    replay = uniform(
        (
            "replay_request_identity",
            "replay_request_sha256",
            "replay_nonce_identity",
            "replay_nonce_sha256",
        ),
        "replay",
    )
    artifacts = uniform(
        tuple(
            field
            for prefix in ("certificate", "chain", "fullchain", "response_manifest")
            for field in (f"{prefix}_path", f"{prefix}_identity", f"{prefix}_sha256")
        ),
        "signing artifact",
    )
    evidence = (
        replay,
        present("transaction_identity"),
        present("response_trust_identity"),
        present("sensitive_key_identity"),
        sensitive_removed is True,
        artifacts,
        present("response_signature_path"),
        present("response_signature_identity"),
        present("candidate_stage_identity"),
        present("candidate_destination_identity"),
        present("response_stage_identity"),
        present("response_destination_identity"),
    )

    def state(
        replay: bool,
        transaction: bool,
        trust: bool,
        sensitive_key: bool,
        removed: bool,
        artifacts: bool,
        signature_path: bool,
        signature: bool,
        candidate_stage: bool = False,
        candidate_destination: bool = False,
        response_stage: bool = False,
        response_destination: bool = False,
    ) -> tuple[bool, ...]:
        return (
            replay,
            transaction,
            trust,
            sensitive_key,
            removed,
            artifacts,
            signature_path,
            signature,
            candidate_stage,
            candidate_destination,
            response_stage,
            response_destination,
        )

    if phase is SigningPhase.PLANNED:
        index = SIGNING_PLANNED_STEPS.index(recovery_step)
        allowed = {
            state(
                index >= SIGNING_PLANNED_STEPS.index(SigningRecoveryStep.REPLAY_RESERVED),
                index
                >= SIGNING_PLANNED_STEPS.index(
                    SigningRecoveryStep.TRANSACTION_STAGED
                ),
                index
                >= SIGNING_PLANNED_STEPS.index(
                    SigningRecoveryStep.TRANSACTION_STAGED
                ),
                index >= SIGNING_PLANNED_STEPS.index(SigningRecoveryStep.SIGNING_READY),
                index
                >= SIGNING_PLANNED_STEPS.index(
                    SigningRecoveryStep.SENSITIVE_KEY_REMOVED
                ),
                index
                >= SIGNING_PLANNED_STEPS.index(SigningRecoveryStep.SIGNING_COMPLETE),
                index
                >= SIGNING_PLANNED_STEPS.index(SigningRecoveryStep.SIGNING_COMPLETE),
                False,
            )
        }
    elif phase is SigningPhase.CA_COMMITTED:
        base = (True, True, True, True, True, True, True)
        if recovery_step is SigningRecoveryStep.CA_COMMITTED:
            allowed = {state(*base, False)}
        elif recovery_step is SigningRecoveryStep.RESPONSE_SIGNED:
            allowed = {
                state(*base, True, *publication)
                for publication in (
                    (False, False, False, False),
                    (True, False, False, False),
                    (True, False, True, False),
                    (True, True, True, False),
                )
            }
        elif recovery_step is SigningRecoveryStep.CANDIDATE_PUBLISHED:
            allowed = {
                state(*base, True, True, True, True, response_destination)
                for response_destination in (False, True)
            }
        else:
            allowed = {state(*base, True, True, True, True, True)}
    elif committed:
        allowed = {state(True, True, True, True, True, True, True, True, True, True, True, True)}
    else:
        allowed = {
            state(True, True, False, False, True, False, False, False),
            state(True, True, True, False, True, False, False, False),
            state(True, True, True, True, True, False, False, False),
            state(True, True, True, True, True, True, True, False),
        }
    if evidence not in allowed:
        raise CsrRecoveryError(
            "CSR signing checkpoint evidence conflicts with its durable writer state"
        )


def parse_signing_journal(
    data: bytes,
    *,
    pki_dir: os.PathLike[str] | str,
    active_intermediate_dir: os.PathLike[str] | str | None = None,
) -> SigningJournal:
    """Parse and semantically validate a final-Bash CSR signing journal."""

    record = parse_signing_journal_structure(data)
    root = _canonical_pki_dir(pki_dir)
    expected_intermediate = (
        None
        if active_intermediate_dir is None
        else _canonical_pki_dir(active_intermediate_dir)
    )
    request_id = _expect_pattern(record["request_id"], _REQUEST_ID, "request_id")
    nonce = _expect_pattern(record["nonce"], _NONCE, "nonce")
    operation_kind = _enum(CsrOperationKind, record["operation_kind"], "operation_kind")
    _expect_pattern(record["service"], _SERVICE, "service")
    for field in (
        "target",
        "requester_principal",
        "approver_principal",
        "response_principal",
    ):
        _expect_pattern(record[field], _PRINCIPAL, field)
    if record["requester_principal"] != record["target"]:
        raise CsrRecoveryError("CSR signing requester principal does not match target")
    committed = _boolean(record["committed"], "committed")
    phase = _enum(SigningPhase, record["phase"], "phase")
    recovery_step = _enum(
        SigningRecoveryStep, record["recovery_step"], "recovery_step"
    )
    if phase is SigningPhase.PLANNED:
        valid_state = not committed and recovery_step in SIGNING_PLANNED_STEPS
    elif phase is SigningPhase.CA_COMMITTED:
        valid_state = committed and recovery_step in SIGNING_COMMITTED_STEPS
    else:
        valid_state = recovery_step is SigningRecoveryStep.JOURNAL_CLEANUP_PENDING
    if not valid_state:
        raise CsrRecoveryError(
            "CSR signing phase, committed state, and recovery step are inconsistent"
        )
    if record["transaction"] != f"csr-{request_id}":
        raise CsrRecoveryError("CSR signing transaction does not match request_id")

    for field in (
        "request_sha256",
        "approval_sha256",
        "inventory_sha256",
        "csr_sha256",
        "csr_spki_sha256",
    ):
        _digest(record[field], field)
    _digest(record["current_cert_sha256"], "current_cert_sha256", allow_none=True)
    if operation_kind is CsrOperationKind.ISSUE:
        if record["current_cert_sha256"] != "none":
            raise CsrRecoveryError("issue CSR signing journal has a predecessor digest")
    elif record["current_cert_sha256"] == "none":
        raise CsrRecoveryError("renewal or migration CSR journal lacks a predecessor digest")
    created = _expect_pattern(record["created_epoch"], _EPOCH, "created_epoch")

    transaction = record["transaction"]
    transaction_dir = os.path.join(root, "state", "csr", "transactions", transaction)
    signing_dir = os.path.join(transaction_dir, "signing")
    expected_paths = {
        "transaction_dir": transaction_dir,
        "response_trust_path": os.path.join(
            transaction_dir, "responses.allowed_signers"
        ),
        "sensitive_key_path": os.path.join(
            signing_dir, "private", "intermediate-ca.key"
        ),
        "candidate_stage": os.path.join(transaction_dir, "candidate.publish"),
        "candidate_destination": os.path.join(
            root, "state", "csr", "candidates", record["service"], request_id
        ),
        "response_stage": os.path.join(transaction_dir, "response.publish"),
        "response_destination": os.path.join(
            root, "state", "csr", "responses", record["service"], request_id
        ),
        "replay_request_path": os.path.join(
            root, "state", "csr", "replay", "requests", request_id
        ),
        "replay_nonce_path": os.path.join(
            root, "state", "csr", "replay", "nonces", nonce
        ),
    }
    paths: dict[str, str | None] = {
        field: _expect_path(record[field], expected, field)
        for field, expected in expected_paths.items()
    }
    artifact_paths = {
        "certificate_path": os.path.join(signing_dir, "tls.crt"),
        "chain_path": os.path.join(signing_dir, "ca-chain.crt"),
        "fullchain_path": os.path.join(signing_dir, "fullchain.crt"),
        "response_manifest_path": os.path.join(signing_dir, "response"),
        "response_signature_path": os.path.join(signing_dir, "response.sig"),
    }
    for field, expected in artifact_paths.items():
        paths[field] = _optional_exact_path(record[field], expected, field)

    none = frozenset((IdentitySentinel.NONE,))
    identities: dict[str, ParsedIdentity] = {
        "transaction_identity": _identity(
            record["transaction_identity"],
            "transaction_identity",
            "directory",
            sentinels=none,
        )
    }
    for field in (
        "candidate_stage_identity",
        "candidate_destination_identity",
        "response_stage_identity",
        "response_destination_identity",
    ):
        _optional_identity(record, identities, field, "directory")
    for identity_field, digest_field in (
        ("response_trust_identity", "response_trust_sha256"),
        ("replay_request_identity", "replay_request_sha256"),
        ("replay_nonce_identity", "replay_nonce_sha256"),
    ):
        _optional_digest_identity_pair(
            record, identities, identity_field, digest_field
        )
    _optional_identity(record, identities, "sensitive_key_identity", "file")
    if record["sensitive_key_removed"] == "none":
        sensitive_removed = None
    elif record["sensitive_key_removed"] == "true":
        sensitive_removed = True
    else:
        raise CsrRecoveryError("CSR signing sensitive_key_removed is invalid")
    early_sensitive_steps = {
        SigningRecoveryStep.PLANNED,
        SigningRecoveryStep.REPLAY_RESERVED,
        SigningRecoveryStep.TRANSACTION_STAGED,
    }
    staged_sensitive_steps = {
        SigningRecoveryStep.SIGNING_READY,
        SigningRecoveryStep.SIGNING_COMPLETE,
    }
    if phase is SigningPhase.TERMINAL:
        sensitive_valid = sensitive_removed is True
        if committed:
            sensitive_valid = (
                sensitive_valid and record["sensitive_key_identity"] != "none"
            )
    elif recovery_step in early_sensitive_steps:
        sensitive_valid = (
            record["sensitive_key_identity"] == "none"
            and sensitive_removed is None
        )
    elif recovery_step in staged_sensitive_steps:
        sensitive_valid = (
            record["sensitive_key_identity"] != "none"
            and sensitive_removed is None
        )
    else:
        sensitive_valid = (
            record["sensitive_key_identity"] != "none"
            and sensitive_removed is True
        )
    if not sensitive_valid:
        raise CsrRecoveryError(
            "CSR signing sensitive-key evidence is inconsistent with its checkpoint"
        )

    for path_field, identity_field, digest_field in (
        ("certificate_path", "certificate_identity", "certificate_sha256"),
        ("chain_path", "chain_identity", "chain_sha256"),
        ("fullchain_path", "fullchain_identity", "fullchain_sha256"),
        (
            "response_manifest_path",
            "response_manifest_identity",
            "response_manifest_sha256",
        ),
    ):
        _optional_digest_identity_pair(
            record, identities, identity_field, digest_field
        )
        if (record[path_field] == "none") != (record[identity_field] == "none"):
            raise CsrRecoveryError(f"CSR signing evidence {path_field} is incomplete")
    _optional_digest_identity_pair(
        record,
        identities,
        "response_signature_identity",
        "response_signature_sha256",
    )
    if record["response_signature_path"] == "none" and (
        record["response_signature_identity"] != "none"
        or record["response_signature_sha256"] != "none"
    ):
        raise CsrRecoveryError("CSR response signature has evidence without a path")

    for destination, stage in (
        ("candidate_destination_identity", "candidate_stage_identity"),
        ("response_destination_identity", "response_stage_identity"),
    ):
        if record[destination] != "none" and record[destination] != record[stage]:
            raise CsrRecoveryError("CSR publication stage and destination differ")

    issued_serial: str | None = None
    journal_intermediate_dir: str | None = None
    if record["db_index_path"] == "none":
        for key in CSR_DB_KEYS:
            for suffix in CSR_DB_SUFFIXES:
                if record[f"db_{key}_{suffix}"] != "none":
                    raise CsrRecoveryError("CSR signing journal has a partial DB contract")
            for suffix, kind in (
                ("pre_identity", "file"),
                ("source_identity", "file"),
                ("source_object", "object"),
                ("post_identity", "file"),
                ("backup_identity", "file"),
            ):
                field = f"db_{key}_{suffix}"
                identities[field] = _identity(
                    record[field], field, kind, sentinels=none
                )
            for suffix in ("path", "source", "backup"):
                paths[f"db_{key}_{suffix}"] = None
        if committed:
            raise CsrRecoveryError("committed CSR signing journal has no DB contract")
        if phase is SigningPhase.PLANNED and recovery_step not in early_sensitive_steps:
            raise CsrRecoveryError("CSR signing checkpoint is missing its DB contract")
        if phase is SigningPhase.TERMINAL and record["sensitive_key_identity"] != "none":
            raise CsrRecoveryError("terminal CSR signing DB and key evidence conflict")
    else:
        newcert = record["db_newcert_path"]
        issued_serial = os.path.basename(newcert).removesuffix(".pem")
        _expect_pattern(issued_serial, _SERIAL, "db_newcert_path serial")
        if len(issued_serial) > 2 and issued_serial.startswith("00"):
            raise CsrRecoveryError(
                "CSR signing journal db_newcert_path serial is not canonical"
            )
        index_path = record["db_index_path"]
        if (
            expected_intermediate is not None
            and index_path != os.path.join(expected_intermediate, "index.txt")
        ):
            raise CsrRecoveryError(
                "CSR recovery CA path is outside the active intermediate: index"
            )
        journal_intermediate_dir = os.path.dirname(index_path)
        intermediate_parent = os.path.join(root, "authorities", "intermediates")
        relative = os.path.relpath(journal_intermediate_dir, intermediate_parent)
        if (
            not os.path.isabs(journal_intermediate_dir)
            or os.path.normpath(journal_intermediate_dir) != journal_intermediate_dir
            or relative in {".", ".."}
            or relative.startswith(f"..{os.sep}")
            or os.sep in relative
        ):
            raise CsrRecoveryError("CSR signing intermediate DB directory is invalid")
        if (
            expected_intermediate is not None
            and journal_intermediate_dir != expected_intermediate
        ):
            raise CsrRecoveryError(
                "CSR signing DB directory does not match the active intermediate"
            )
        for key, template in CSR_DB_PATHS:
            relative_path = template.format(serial=issued_serial)
            expected = {
                f"db_{key}_path": os.path.join(
                    journal_intermediate_dir, relative_path
                ),
                f"db_{key}_source": os.path.join(signing_dir, relative_path),
                f"db_{key}_backup": os.path.join(
                    transaction_dir, "ca-backup", key
                ),
            }
            for field, value in expected.items():
                paths[field] = _expect_path(record[field], value, field)
            identities[f"db_{key}_pre_identity"] = _identity(
                record[f"db_{key}_pre_identity"],
                f"db_{key}_pre_identity",
                "file",
                sentinels=frozenset((IdentitySentinel.ABSENT,)),
            )
            _optional_identity(
                record, identities, f"db_{key}_source_identity", "file"
            )
            _optional_identity(
                record, identities, f"db_{key}_source_object", "object"
            )
            if (record[f"db_{key}_source_identity"] == "none") != (
                record[f"db_{key}_source_object"] == "none"
            ):
                raise CsrRecoveryError(f"CSR signing DB source {key} is incomplete")
            _optional_identity(
                record, identities, f"db_{key}_post_identity", "file"
            )
            _optional_identity(
                record, identities, f"db_{key}_backup_identity", "file"
            )
            backup_expected = record[f"db_{key}_pre_identity"] != "absent"
            if backup_expected != (record[f"db_{key}_backup_identity"] != "none"):
                raise CsrRecoveryError(f"CSR signing DB backup {key} is inconsistent")

        source_present = tuple(
            record[f"db_{key}_source_identity"] != "none" for key in CSR_DB_KEYS
        )
        if len(set(source_present)) != 1:
            raise CsrRecoveryError("CSR signing DB source evidence is incomplete")
        all_sources_present = all(source_present)
        if phase is SigningPhase.TERMINAL and not committed:
            source_expected: bool | None = None
        else:
            source_expected = (
                phase is SigningPhase.CA_COMMITTED
                or phase is SigningPhase.TERMINAL
                or SIGNING_PLANNED_STEPS.index(recovery_step)
                >= SIGNING_PLANNED_STEPS.index(SigningRecoveryStep.SIGNING_COMPLETE)
            )
        if source_expected is not None and all_sources_present != source_expected:
            raise CsrRecoveryError(
                "CSR signing DB source evidence conflicts with its checkpoint"
            )

        post_present = tuple(
            record[f"db_{key}_post_identity"] != "none" for key in CSR_DB_KEYS
        )
        post_count = sum(post_present)
        if post_present != tuple(
            index < post_count for index in range(len(CSR_DB_KEYS))
        ):
            raise CsrRecoveryError("CSR signing DB post identities are not a prefix")
        if phase is SigningPhase.PLANNED:
            expected_post_count = (
                SIGNING_POST_STEPS.index(recovery_step) + 1
                if recovery_step in SIGNING_POST_STEPS
                else 0
            )
        elif committed:
            expected_post_count = len(CSR_DB_KEYS)
        else:
            expected_post_count = post_count
        if post_count != expected_post_count:
            raise CsrRecoveryError(
                "CSR signing DB post identities conflict with its checkpoint"
            )
        if post_count and not all_sources_present:
            raise CsrRecoveryError(
                "CSR signing DB post identities have no complete source evidence"
            )
        if phase is SigningPhase.TERMINAL and not committed:
            if not all_sources_present and post_count:
                raise CsrRecoveryError(
                    "terminal CSR signing DB evidence is inconsistent"
                )
            if record["sensitive_key_identity"] == "none":
                raise CsrRecoveryError(
                    "terminal CSR signing DB and key evidence conflict"
                )
        elif phase is SigningPhase.PLANNED and recovery_step in early_sensitive_steps:
            raise CsrRecoveryError("early CSR signing checkpoint has a DB contract")

    _validate_signing_checkpoint_evidence(
        record, phase, committed, recovery_step, sensitive_removed
    )

    return SigningJournal(
        record,
        root,
        operation_kind,
        phase,
        recovery_step,
        committed,
        sensitive_removed,
        int(created),
        issued_serial,
        journal_intermediate_dir,
        tuple(sorted(identities.items())),
        tuple(sorted(paths.items())),
    )


def validate_signing_transaction_presence(
    journal: SigningJournal,
    *,
    transaction_exists: bool,
) -> None:
    """Validate the final-Bash transaction existence/identity relationship."""

    if not isinstance(journal, SigningJournal):
        raise TypeError("journal must be a SigningJournal")
    if type(transaction_exists) is not bool:
        raise TypeError("transaction_exists must be boolean")
    identity = journal.identity("transaction_identity")
    if transaction_exists and identity is IdentitySentinel.NONE:
        raise CsrRecoveryError("unowned CSR signing transaction directory appeared")
    if not transaction_exists and (
        identity is not IdentitySentinel.NONE or journal.committed
    ):
        raise CsrRecoveryError("CSR signing transaction directory is missing")


def _generated_stage(value: str, prefix: str, field: str) -> str:
    if not value.startswith(prefix):
        raise CsrRecoveryError(f"CSR finalization path {field} is outside its contract")
    suffix = value[len(prefix) :]
    if _STAGE_SUFFIX.fullmatch(suffix) is None or os.path.normpath(value) != value:
        raise CsrRecoveryError(f"CSR finalization path {field} is not a generated stage")
    return value


def parse_finalization_journal(
    data: bytes,
    *,
    pki_dir: os.PathLike[str] | str,
) -> FinalizationJournal:
    """Parse and semantically validate a final-Bash candidate finalization journal."""

    record = parse_finalization_journal_structure(data)
    root = _canonical_pki_dir(pki_dir)
    service = _expect_pattern(record["service"], _SERVICE, "service")
    request_id = _expect_pattern(record["request_id"], _REQUEST_ID, "request_id")
    phase = _enum(FinalizationPhase, record["phase"], "phase")
    active_mode = _enum(ActivePublicationMode, record["active_mode"], "active_mode")

    outcome_parent = os.path.join(root, "state", "csr", "outcomes", service)
    active_parent = os.path.join(root, "state", "csr", "active")
    candidate_dir = os.path.join(
        root, "state", "csr", "candidates", service, request_id
    )
    response_dir = os.path.join(
        root, "state", "csr", "responses", service, request_id
    )
    artifact_dir = os.path.join(
        root, "export", "certificates", "v1", "artifacts", service, request_id
    )
    transaction_dir = os.path.join(
        root, "state", "csr", "transactions", f"csr-{request_id}"
    )
    paths = {
        "outcome_stage": _generated_stage(
            record["outcome_stage"],
            os.path.join(
                outcome_parent, f".platform-pki-csr-outcome.{request_id}."
            ),
            "outcome_stage",
        ),
        "outcome_destination": _expect_path(
            record["outcome_destination"],
            os.path.join(outcome_parent, request_id),
            "outcome_destination",
        ),
        "active_stage": _generated_stage(
            record["active_stage"],
            os.path.join(active_parent, f".platform-pki-active.{service}."),
            "active_stage",
        ),
        "active_destination": _expect_path(
            record["active_destination"],
            os.path.join(active_parent, service),
            "active_destination",
        ),
        "candidate_dir": _expect_path(
            record["candidate_dir"], candidate_dir, "candidate_dir"
        ),
        "candidate_path": _expect_path(
            record["candidate_path"],
            os.path.join(candidate_dir, "candidate"),
            "candidate_path",
        ),
        "response_dir": _expect_path(
            record["response_dir"], response_dir, "response_dir"
        ),
        "response_path": _expect_path(
            record["response_path"],
            os.path.join(response_dir, "response"),
            "response_path",
        ),
        "response_signature_path": _expect_path(
            record["response_signature_path"],
            os.path.join(response_dir, "response.sig"),
            "response_signature_path",
        ),
        "artifact_dir": _expect_path(
            record["artifact_dir"], artifact_dir, "artifact_dir"
        ),
        "artifact_path": _expect_path(
            record["artifact_path"],
            os.path.join(artifact_dir, "artifact"),
            "artifact_path",
        ),
        "transaction_dir": _expect_path(
            record["transaction_dir"], transaction_dir, "transaction_dir"
        ),
        "response_trust_path": _expect_path(
            record["response_trust_path"],
            os.path.join(transaction_dir, "responses.allowed_signers"),
            "response_trust_path",
        ),
    }

    identities: dict[str, ParsedIdentity] = {}
    for field in (
        "outcome_stage_identity",
        "candidate_dir_identity",
        "response_dir_identity",
        "transaction_dir_identity",
        "artifact_dir_identity",
    ):
        identities[field] = _identity(record[field], field, "directory")
    identities["outcome_destination_identity"] = _identity(
        record["outcome_destination_identity"],
        "outcome_destination_identity",
        "directory",
        sentinels=frozenset((IdentitySentinel.NONE,)),
    )
    for field in ("active_stage_identity", "active_pre_identity"):
        identities[field] = _identity(
            record[field],
            field,
            "object",
            sentinels=(
                frozenset((IdentitySentinel.ABSENT,))
                if field == "active_pre_identity"
                else frozenset()
            ),
        )
    identities["active_destination_identity"] = _identity(
        record["active_destination_identity"],
        "active_destination_identity",
        "object",
        sentinels=frozenset((IdentitySentinel.NONE,)),
    )
    file_identity_fields = (
        "response_trust_identity",
        "candidate_identity",
        "artifact_identity",
        "response_identity",
        "response_signature_identity",
        "outcome_deployment_identity",
        "outcome_deployment_signature_identity",
        "outcome_deployers_identity",
        "outcome_decision_identity",
        *(f"source_{key}_identity" for key in CANDIDATE_SOURCE_KEYS),
    )
    for field in file_identity_fields:
        identities[field] = _identity(record[field], field, "file")

    digest_fields = (
        "response_trust_sha256",
        "candidate_sha256",
        "artifact_sha256",
        "response_sha256",
        "response_signature_sha256",
        "deployment_sha256",
        "deployment_signature_sha256",
        "deployers_sha256",
        "decision_sha256",
        "active_sha256",
        *(f"source_{key}_sha256" for key in CANDIDATE_SOURCE_KEYS),
    )
    for field in digest_fields:
        _digest(record[field], field)

    if active_mode is ActivePublicationMode.CREATE:
        if (
            record["active_pre_identity"] != "absent"
            or record["active_pre_sha256"] != "none"
        ):
            raise CsrRecoveryError("CSR finalization create mode has a predecessor")
    else:
        if record["active_pre_identity"] == "absent":
            raise CsrRecoveryError("CSR finalization exchange mode lacks a predecessor")
        _digest(record["active_pre_sha256"], "active_pre_sha256")

    if phase is FinalizationPhase.PLANNED:
        expected_outcome = expected_active = "none"
    elif phase is FinalizationPhase.OUTCOME_PUBLISHED:
        expected_outcome = record["outcome_stage_identity"]
        expected_active = "none"
    else:
        expected_outcome = record["outcome_stage_identity"]
        expected_active = record["active_stage_identity"]
    if (
        record["outcome_destination_identity"] != expected_outcome
        or record["active_destination_identity"] != expected_active
    ):
        raise CsrRecoveryError("CSR finalization phase identities are inconsistent")

    source_roots = {
        "candidate": candidate_dir,
        "response": response_dir,
        "artifact": artifact_dir,
    }
    source_paths = tuple(
        (key, os.path.join(source_roots[source_root], name))
        for key, source_root, name in CANDIDATE_SOURCE_PATHS
    )
    main_source_bindings = {
        "candidate": "source_candidate_candidate",
        "artifact": "source_artifact_artifact",
        "response": "source_response_response",
        "response_signature": "source_response_response_sig",
    }
    for field, source_field in main_source_bindings.items():
        if (
            record[f"{field}_identity"] != record[f"{source_field}_identity"]
            or record[f"{field}_sha256"] != record[f"{source_field}_sha256"]
        ):
            raise CsrRecoveryError(f"CSR finalization source evidence {field} conflicts")

    return FinalizationJournal(
        record,
        root,
        phase,
        active_mode,
        tuple(sorted(identities.items())),
        tuple(sorted(paths.items())),
        source_paths,
    )
