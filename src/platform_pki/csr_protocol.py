"""Canonical typed models for the retained host-local CSR protocol records."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from hashlib import sha256

from .records import OrderedRecord, RecordError, RecordSpec


def _fields(value: str) -> tuple[str, ...]:
    return tuple(value.split())


CSR_REQUEST_FIELDS = _fields("""
schema request_id nonce created_epoch expires_epoch operation service target
requester_principal inventory_sha256 csr_sha256 csr_spki_sha256
current_cert_sha256 profile response_principal
""")
CSR_APPROVAL_FIELDS = _fields("""
schema request_id nonce created_epoch expires_epoch approver_principal
request_sha256 csr_sha256 inventory_sha256 operation service target profile
""")
CSR_RESPONSE_FIELDS = _fields("""
schema request_id nonce operation service target request_sha256 approval_sha256
inventory_sha256 csr_sha256 csr_spki_sha256 certificate_sha256
certificate_spki_sha256 chain_sha256 issuer_root issuer_intermediate serial
not_before_epoch not_after_epoch candidate_state response_principal created_epoch
""")
CSR_CANDIDATE_FIELDS = _fields("""
schema request_id nonce operation service target state request_sha256
approval_sha256 inventory_sha256 csr_sha256 csr_spki_sha256 certificate_sha256
chain_sha256 issuer_root issuer_intermediate serial response_sha256
response_signature_sha256 created_epoch
""")
CSR_REPLAY_REQUEST_FIELDS = (
    "schema",
    "request_id",
    "nonce",
    "operation",
    "service",
    "target",
    "request_sha256",
    "approval_sha256",
    "outcome",
)
CSR_REPLAY_NONCE_FIELDS = (
    "schema",
    "nonce",
    "request_id",
    "request_sha256",
    "outcome",
)
CSR_TERMINAL_FIELDS = (
    "schema",
    "transaction",
    "request_id",
    "operation",
    "service",
    "outcome",
    "committed",
)

CSR_REQUEST_SPEC = RecordSpec(CSR_REQUEST_FIELDS, schema="1")
CSR_APPROVAL_SPEC = RecordSpec(CSR_APPROVAL_FIELDS, schema="1")
CSR_RESPONSE_SPEC = RecordSpec(CSR_RESPONSE_FIELDS, schema="1")
CSR_CANDIDATE_SPEC = RecordSpec(CSR_CANDIDATE_FIELDS, schema="1")
CSR_REPLAY_REQUEST_SPEC = RecordSpec(CSR_REPLAY_REQUEST_FIELDS, schema="1")
CSR_REPLAY_NONCE_SPEC = RecordSpec(CSR_REPLAY_NONCE_FIELDS, schema="1")
CSR_TERMINAL_SPEC = RecordSpec(CSR_TERMINAL_FIELDS, schema="1")

CSR_REQUEST_MAX_AGE_SECONDS = 604_800
CSR_APPROVAL_MAX_AGE_SECONDS = 86_400
CSR_SOLE_OPERATOR_MIN_DELAY_SECONDS = 86_400


class CsrProtocolError(ValueError):
    """A canonical CSR protocol record violates the retained shell contract."""


class CsrOperation(Enum):
    ISSUE = "issue"
    MIGRATE = "migrate"
    RENEW = "renew"


class CsrTerminalOutcome(Enum):
    PUBLISHED = "published"
    FAILED_PRE_COMMIT = "failed-pre-commit"


_REQUEST_ID = re.compile(r"[0-9a-f]{32}", re.ASCII)
_NONCE = re.compile(r"[0-9a-f]{64}", re.ASCII)
_DIGEST = re.compile(r"[0-9a-f]{64}", re.ASCII)
_EPOCH = re.compile(r"0|[1-9][0-9]*", re.ASCII)
_SERVICE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*", re.ASCII)
_PRINCIPAL = re.compile(r"[a-z0-9][a-z0-9.-]*", re.ASCII)
_ROOT_GENERATION = re.compile(r"g[1-9][0-9]*", re.ASCII)
_INTERMEDIATE_GENERATION = re.compile(r"g[1-9][0-9]*-i[1-9][0-9]*", re.ASCII)
_SERIAL = re.compile(r"(?:[0-9A-F]{2})+", re.ASCII)
_PROFILE = "server-p384-sha384-v1"


@dataclass(frozen=True, slots=True)
class CsrRequest:
    record: OrderedRecord
    operation: CsrOperation
    created_epoch: int
    expires_epoch: int

    def to_bytes(self) -> bytes:
        return self.record.to_bytes()


@dataclass(frozen=True, slots=True)
class CsrApproval:
    record: OrderedRecord
    operation: CsrOperation
    created_epoch: int
    expires_epoch: int

    def to_bytes(self) -> bytes:
        return self.record.to_bytes()


@dataclass(frozen=True, slots=True)
class CsrResponse:
    record: OrderedRecord
    operation: CsrOperation
    not_before_epoch: int
    not_after_epoch: int
    created_epoch: int

    def to_bytes(self) -> bytes:
        return self.record.to_bytes()


@dataclass(frozen=True, slots=True)
class CsrCandidate:
    record: OrderedRecord
    operation: CsrOperation
    created_epoch: int

    def to_bytes(self) -> bytes:
        return self.record.to_bytes()


@dataclass(frozen=True, slots=True)
class CsrReplayRequest:
    record: OrderedRecord
    operation: CsrOperation

    def to_bytes(self) -> bytes:
        return self.record.to_bytes()


@dataclass(frozen=True, slots=True)
class CsrReplayNonce:
    record: OrderedRecord

    def to_bytes(self) -> bytes:
        return self.record.to_bytes()


@dataclass(frozen=True, slots=True)
class CsrTerminal:
    record: OrderedRecord
    operation: CsrOperation
    outcome: CsrTerminalOutcome
    committed: bool

    def to_bytes(self) -> bytes:
        return self.record.to_bytes()


def _parse(data: bytes, spec: RecordSpec) -> OrderedRecord:
    try:
        return spec.parse(data)
    except RecordError as error:
        raise CsrProtocolError(str(error)) from None


def _pattern(record: OrderedRecord, field: str, pattern: re.Pattern[str]) -> str:
    value = record[field]
    if pattern.fullmatch(value) is None:
        raise CsrProtocolError(f"CSR protocol field {field} is invalid")
    return value


def _operation(record: OrderedRecord) -> CsrOperation:
    try:
        return CsrOperation(record["operation"])
    except ValueError:
        raise CsrProtocolError("CSR protocol operation is invalid") from None


def _epoch(record: OrderedRecord, field: str) -> int:
    return int(_pattern(record, field, _EPOCH))


def _serial(record: OrderedRecord) -> str:
    serial = _pattern(record, "serial", _SERIAL)
    if len(serial) > 2 and serial.startswith("00"):
        raise CsrProtocolError("CSR protocol field serial is not canonical")
    return serial


def _digest(record: OrderedRecord, field: str, *, allow_none: bool = False) -> None:
    if allow_none and record[field] == "none":
        return
    _pattern(record, field, _DIGEST)


def _identity_fields(record: OrderedRecord, *, nonce: bool = True) -> None:
    _pattern(record, "request_id", _REQUEST_ID)
    if nonce:
        _pattern(record, "nonce", _NONCE)


def _service_target(record: OrderedRecord) -> None:
    _pattern(record, "service", _SERVICE)
    _pattern(record, "target", _PRINCIPAL)


def parse_csr_request(data: bytes) -> CsrRequest:
    record = _parse(data, CSR_REQUEST_SPEC)
    _identity_fields(record)
    _service_target(record)
    _pattern(record, "requester_principal", _PRINCIPAL)
    _pattern(record, "response_principal", _PRINCIPAL)
    if record["requester_principal"] != record["target"]:
        raise CsrProtocolError(
            "CSR requester principal must exactly match the target identity"
        )
    operation = _operation(record)
    for field in ("inventory_sha256", "csr_sha256", "csr_spki_sha256"):
        _digest(record, field)
    _digest(record, "current_cert_sha256", allow_none=True)
    if (operation is CsrOperation.ISSUE) != (record["current_cert_sha256"] == "none"):
        raise CsrProtocolError("CSR request predecessor does not match operation")
    if record["profile"] != _PROFILE:
        raise CsrProtocolError("CSR request profile is invalid")
    created = _epoch(record, "created_epoch")
    expires = _epoch(record, "expires_epoch")
    if expires <= created:
        raise CsrProtocolError("CSR request validity interval is invalid")
    if expires - created > CSR_REQUEST_MAX_AGE_SECONDS:
        raise CsrProtocolError("CSR request validity interval exceeds policy")
    return CsrRequest(record, operation, created, expires)


def parse_csr_approval_record(data: bytes) -> OrderedRecord:
    return _parse(data, CSR_APPROVAL_SPEC)


def parse_csr_approval(data: bytes) -> CsrApproval:
    record = parse_csr_approval_record(data)
    _identity_fields(record)
    _service_target(record)
    _pattern(record, "approver_principal", _PRINCIPAL)
    operation = _operation(record)
    for field in ("request_sha256", "csr_sha256", "inventory_sha256"):
        _digest(record, field)
    if record["profile"] != _PROFILE:
        raise CsrProtocolError("CSR approval profile is invalid")
    created = _epoch(record, "created_epoch")
    expires = _epoch(record, "expires_epoch")
    if expires <= created:
        raise CsrProtocolError("CSR approval validity interval is invalid")
    if expires - created > CSR_APPROVAL_MAX_AGE_SECONDS:
        raise CsrProtocolError("CSR approval validity interval exceeds policy")
    return CsrApproval(record, operation, created, expires)


def validate_request_approval_binding(
    request: CsrRequest,
    approval: CsrApproval,
    *,
    signer_keys_match: bool | None = None,
) -> None:
    """Validate record-only binding and caller-authenticated signer-key timing.

    Signature verification, signer trust resolution, and current-time freshness
    remain live protocol checks.  A caller that has resolved both trusted signer
    keys may pass whether they match to apply the retained sole-operator delay.
    """

    if not isinstance(request, CsrRequest) or not isinstance(approval, CsrApproval):
        raise TypeError("request and approval must be typed CSR protocol records")
    if signer_keys_match is not None and not isinstance(signer_keys_match, bool):
        raise TypeError("signer_keys_match must be a bool or None")
    for field in (
        "request_id",
        "nonce",
        "operation",
        "service",
        "target",
        "csr_sha256",
        "inventory_sha256",
        "profile",
    ):
        if request.record[field] != approval.record[field]:
            raise CsrProtocolError(f"CSR approval does not bind request field: {field}")
    if approval.record["request_sha256"] != sha256(request.to_bytes()).hexdigest():
        raise CsrProtocolError("CSR approval does not bind canonical request bytes")
    if approval.created_epoch < request.created_epoch:
        raise CsrProtocolError("CSR approval predates its request")
    if (
        signer_keys_match is True
        and approval.created_epoch - request.created_epoch
        < CSR_SOLE_OPERATOR_MIN_DELAY_SECONDS
    ):
        raise CsrProtocolError("sole-operator CSR approval delay has not elapsed")


def parse_csr_response(data: bytes) -> CsrResponse:
    record = _parse(data, CSR_RESPONSE_SPEC)
    _identity_fields(record)
    _service_target(record)
    operation = _operation(record)
    for field in (
        "request_sha256",
        "approval_sha256",
        "inventory_sha256",
        "csr_sha256",
        "csr_spki_sha256",
        "certificate_sha256",
        "certificate_spki_sha256",
        "chain_sha256",
    ):
        _digest(record, field)
    if record["csr_spki_sha256"] != record["certificate_spki_sha256"]:
        raise CsrProtocolError("CSR response SPKI binding is invalid")
    root = _pattern(record, "issuer_root", _ROOT_GENERATION)
    intermediate = _pattern(record, "issuer_intermediate", _INTERMEDIATE_GENERATION)
    if not intermediate.startswith(f"{root}-i"):
        raise CsrProtocolError("CSR response issuer generations do not match")
    _serial(record)
    _pattern(record, "response_principal", _PRINCIPAL)
    if record["candidate_state"] != "pending":
        raise CsrProtocolError("CSR response candidate state is invalid")
    not_before = _epoch(record, "not_before_epoch")
    not_after = _epoch(record, "not_after_epoch")
    created = _epoch(record, "created_epoch")
    if not_after <= not_before:
        raise CsrProtocolError("CSR response validity interval is invalid")
    return CsrResponse(record, operation, not_before, not_after, created)


def parse_csr_candidate(data: bytes) -> CsrCandidate:
    record = _parse(data, CSR_CANDIDATE_SPEC)
    _identity_fields(record)
    _service_target(record)
    operation = _operation(record)
    for field in (
        "request_sha256",
        "approval_sha256",
        "inventory_sha256",
        "csr_sha256",
        "csr_spki_sha256",
        "certificate_sha256",
        "chain_sha256",
        "response_sha256",
        "response_signature_sha256",
    ):
        _digest(record, field)
    root = _pattern(record, "issuer_root", _ROOT_GENERATION)
    intermediate = _pattern(record, "issuer_intermediate", _INTERMEDIATE_GENERATION)
    if not intermediate.startswith(f"{root}-i"):
        raise CsrProtocolError("CSR candidate issuer generations do not match")
    _serial(record)
    if record["state"] != "pending":
        raise CsrProtocolError("CSR candidate state is invalid")
    return CsrCandidate(record, operation, _epoch(record, "created_epoch"))


def validate_response_candidate_binding(
    response: CsrResponse, candidate: CsrCandidate
) -> None:
    if not isinstance(response, CsrResponse) or not isinstance(candidate, CsrCandidate):
        raise TypeError("response and candidate must be typed CSR protocol records")
    for field in (
        "request_id",
        "nonce",
        "operation",
        "service",
        "target",
        "request_sha256",
        "approval_sha256",
        "inventory_sha256",
        "csr_sha256",
        "csr_spki_sha256",
        "certificate_sha256",
        "chain_sha256",
        "issuer_root",
        "issuer_intermediate",
        "serial",
        "created_epoch",
    ):
        if response.record[field] != candidate.record[field]:
            raise CsrProtocolError(f"CSR candidate does not bind response field {field}")
    if candidate.record["response_sha256"] != sha256(response.to_bytes()).hexdigest():
        raise CsrProtocolError("CSR candidate does not bind canonical response bytes")


def parse_csr_replay_request(data: bytes) -> CsrReplayRequest:
    record = _parse(data, CSR_REPLAY_REQUEST_SPEC)
    _identity_fields(record)
    _service_target(record)
    operation = _operation(record)
    for field in ("request_sha256", "approval_sha256"):
        _digest(record, field)
    if record["outcome"] != "reserved":
        raise CsrProtocolError("CSR replay request outcome is invalid")
    return CsrReplayRequest(record, operation)


def parse_csr_replay_nonce(data: bytes) -> CsrReplayNonce:
    record = _parse(data, CSR_REPLAY_NONCE_SPEC)
    _identity_fields(record)
    _digest(record, "request_sha256")
    if record["outcome"] != "reserved":
        raise CsrProtocolError("CSR replay nonce outcome is invalid")
    return CsrReplayNonce(record)


def parse_csr_terminal(data: bytes) -> CsrTerminal:
    record = _parse(data, CSR_TERMINAL_SPEC)
    _identity_fields(record, nonce=False)
    operation = _operation(record)
    if record["transaction"] != f"csr-{record['request_id']}":
        raise CsrProtocolError("CSR terminal transaction binding is invalid")
    _pattern(record, "service", _SERVICE)
    try:
        outcome = CsrTerminalOutcome(record["outcome"])
    except ValueError:
        raise CsrProtocolError("CSR terminal outcome is invalid") from None
    if record["committed"] not in {"false", "true"}:
        raise CsrProtocolError("CSR terminal committed field is invalid")
    committed = record["committed"] == "true"
    if committed != (outcome is CsrTerminalOutcome.PUBLISHED):
        raise CsrProtocolError("CSR terminal outcome and commit state conflict")
    return CsrTerminal(record, operation, outcome, committed)


def _serialize(values, spec: RecordSpec, parser) -> bytes:
    if hasattr(values, "record"):
        values = values.record
    try:
        data = spec.serialize(values)
    except RecordError as error:
        raise CsrProtocolError(str(error)) from None
    parser(data)
    return data


def serialize_csr_request(values: Mapping[str, str] | CsrRequest) -> bytes:
    return _serialize(values, CSR_REQUEST_SPEC, parse_csr_request)


def serialize_csr_approval(values: Mapping[str, str] | CsrApproval) -> bytes:
    return _serialize(values, CSR_APPROVAL_SPEC, parse_csr_approval)


def serialize_csr_response(values: Mapping[str, str] | CsrResponse) -> bytes:
    return _serialize(values, CSR_RESPONSE_SPEC, parse_csr_response)


def serialize_csr_candidate(values: Mapping[str, str] | CsrCandidate) -> bytes:
    return _serialize(values, CSR_CANDIDATE_SPEC, parse_csr_candidate)


def serialize_csr_replay_request(
    values: Mapping[str, str] | CsrReplayRequest,
) -> bytes:
    return _serialize(values, CSR_REPLAY_REQUEST_SPEC, parse_csr_replay_request)


def serialize_csr_replay_nonce(values: Mapping[str, str] | CsrReplayNonce) -> bytes:
    return _serialize(values, CSR_REPLAY_NONCE_SPEC, parse_csr_replay_nonce)


def serialize_csr_terminal(values: Mapping[str, str] | CsrTerminal) -> bytes:
    return _serialize(values, CSR_TERMINAL_SPEC, parse_csr_terminal)
