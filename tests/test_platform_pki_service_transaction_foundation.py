from __future__ import annotations

import re
from hashlib import sha256
from pathlib import Path

import pytest

from src.platform_pki import service_transaction as service_model
from src.platform_pki.csr_protocol import (
    CSR_APPROVAL_MAX_AGE_SECONDS,
    CSR_APPROVAL_FIELDS,
    CSR_CANDIDATE_FIELDS,
    CSR_REPLAY_NONCE_FIELDS,
    CSR_REPLAY_REQUEST_FIELDS,
    CSR_REQUEST_FIELDS,
    CSR_REQUEST_MAX_AGE_SECONDS,
    CSR_RESPONSE_FIELDS,
    CSR_TERMINAL_FIELDS,
    CSR_SOLE_OPERATOR_MIN_DELAY_SECONDS,
    CsrOperation,
    CsrProtocolError,
    parse_csr_approval,
    parse_csr_candidate,
    parse_csr_replay_nonce,
    parse_csr_replay_request,
    parse_csr_request,
    parse_csr_response,
    parse_csr_terminal,
    serialize_csr_approval,
    serialize_csr_candidate,
    serialize_csr_replay_nonce,
    serialize_csr_replay_request,
    serialize_csr_request,
    serialize_csr_response,
    serialize_csr_terminal,
    validate_request_approval_binding,
    validate_response_candidate_binding,
)
from src.platform_pki.filesystem import DirectoryIdentity, FileIdentity, FileObjectState
from src.platform_pki.persisted_identity import IdentitySentinel
from src.platform_pki.service_transaction import (
    MANAGED_ISSUE_ARCHIVE_MEMBER_ORDER,
    MANAGED_ISSUE_PUBLICATION_ORDER,
    MANAGED_RENEW_ARCHIVE_MEMBER_ORDER,
    MANAGED_RENEW_PUBLICATION_ORDER,
    SERVICE_CA_PUBLICATION_ORDER,
    SERVICE_CLEANUP_OWNED_KEYS,
    SERVICE_CONTINUITY_KEYS,
    SERVICE_CONTAINER_ORDER,
    SERVICE_RETAINED_TERMINAL_FIELDS,
    SERVICE_RETAINED_ROLLBACK_FIELDS,
    SERVICE_RETAINED_TRANSACTION_FIELDS,
    SERVICE_SIGNING_INPUT_KEYS,
    SERVICE_TRANSACTION_FIELDS,
    SERVICE_TRANSACTION_JOURNAL_RELATIVE_PATH,
    SERVICE_TRANSACTION_LOCK_PROFILE,
    SERVICE_ISSUE_REPLACE_POLICY,
    SERVICE_RENEW_REPLACE_POLICY,
    ServiceArchiveState,
    ServiceKeyAction,
    ServiceOperation,
    ServiceOutcome,
    ServicePhase,
    ServiceRecoveryMode,
    ServiceTransactionError,
    managed_publication_order,
    managed_rollback_order,
    parse_service_transaction,
    parse_service_retained_terminal,
    parse_service_retained_rollback,
    parse_service_retained_transaction,
    serialize_service_retained_terminal,
    serialize_service_retained_rollback,
    serialize_service_retained_transaction,
    serialize_service_transaction,
    service_cleanup_owned_keys,
)


ROOT = Path(__file__).resolve().parents[1]
PKI_DIR = "/srv/platform/pki"
DIGEST = "0" * 64
EMPTY_DIGEST = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
REQUEST_ID = "0123456789abcdef0123456789abcdef"
NONCE = "ab" * 32
OWNER = 1000
DIRECTORY_IDENTITY = "1:2:1000:700:directory"
ARCHIVE_SOURCE_KEYS = {
    "archive_certificate": "service_certificate",
    "archive_csr": "service_csr",
    "archive_chain": "service_chain",
    "archive_fullchain": "service_fullchain",
    "archive_config": "service_config",
    "archive_issuer": "service_issuer",
    "archive_key": "service_key",
}


def _file_identity(
    inode: int,
    *,
    mode: int = 0o600,
    size: int = 1,
    mtime: str = "2026-08-11 12:00:00.000000000 +0000",
    ctime: str = "2026-08-11 12:00:01.000000000 +0000",
) -> str:
    kind = "regular empty file" if size == 0 else "regular file"
    return (
        f"1:{inode}:{OWNER}:{mode:o}:1:{size}:{mtime}:{ctime}:{kind}"
    )


def _object_identity(inode: int, *, mode: int = 0o600, size: int = 1) -> str:
    kind = "regular empty file" if size == 0 else "regular file"
    return f"1:{inode}:{OWNER}:{mode:o}:1:{size}:{kind}"


def _full_directory_identity(
    inode: int,
    *,
    mode: int = 0o700,
    mtime: str = "2026-08-11 12:00:00.000000000 +0000",
    ctime: str = "2026-08-11 12:00:01.000000000 +0000",
) -> str:
    return f"1:{inode}:{OWNER}:{mode:o}:2:4096:{mtime}:{ctime}:directory"


def _directory_identity(inode: int, *, mode: int = 0o700) -> str:
    return f"1:{inode}:{OWNER}:{mode:o}:directory"


def _evidence_digest(label: str) -> str:
    return sha256(label.encode("ascii")).hexdigest()


def _payload(fields: tuple[str, ...], values: dict[str, str]) -> bytes:
    return "".join(f"{field}={values[field]}\n" for field in fields).encode("ascii")


def _request_values() -> dict[str, str]:
    return {
        "schema": "1",
        "request_id": REQUEST_ID,
        "nonce": NONCE,
        "created_epoch": "100",
        "expires_epoch": "200",
        "operation": "issue",
        "service": "External_1",
        "target": "host-01.example",
        "requester_principal": "host-01.example",
        "inventory_sha256": DIGEST,
        "csr_sha256": DIGEST,
        "csr_spki_sha256": DIGEST,
        "current_cert_sha256": "none",
        "profile": "server-p384-sha384-v1",
        "response_principal": "pki-response",
    }


def _approval_values(request: dict[str, str] | None = None) -> dict[str, str]:
    request = _request_values() if request is None else request
    return {
        "schema": "1",
        "request_id": REQUEST_ID,
        "nonce": NONCE,
        "created_epoch": "150",
        "expires_epoch": "190",
        "approver_principal": "pki-approver",
        "request_sha256": sha256(_payload(CSR_REQUEST_FIELDS, request)).hexdigest(),
        "csr_sha256": request["csr_sha256"],
        "inventory_sha256": request["inventory_sha256"],
        "operation": request["operation"],
        "service": request["service"],
        "target": request["target"],
        "profile": request["profile"],
    }


def _response_values() -> dict[str, str]:
    return {
        "schema": "1",
        "request_id": REQUEST_ID,
        "nonce": NONCE,
        "operation": "issue",
        "service": "External_1",
        "target": "host-01.example",
        "request_sha256": DIGEST,
        "approval_sha256": DIGEST,
        "inventory_sha256": DIGEST,
        "csr_sha256": DIGEST,
        "csr_spki_sha256": DIGEST,
        "certificate_sha256": DIGEST,
        "certificate_spki_sha256": DIGEST,
        "chain_sha256": DIGEST,
        "issuer_root": "g1",
        "issuer_intermediate": "g1-i1",
        "serial": "10AF",
        "not_before_epoch": "100",
        "not_after_epoch": "200",
        "candidate_state": "pending",
        "response_principal": "pki-response",
        "created_epoch": "100",
    }


def _candidate_values(response: dict[str, str] | None = None) -> dict[str, str]:
    response = _response_values() if response is None else response
    fields = (
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
    )
    values = {field: response[field] for field in fields}
    values.update(
        schema="1",
        state="pending",
        response_sha256=sha256(_payload(CSR_RESPONSE_FIELDS, response)).hexdigest(),
        response_signature_sha256=DIGEST,
    )
    return values


def _record_cases():
    replay_request = {
        "schema": "1",
        "request_id": REQUEST_ID,
        "nonce": NONCE,
        "operation": "issue",
        "service": "External_1",
        "target": "host-01.example",
        "request_sha256": DIGEST,
        "approval_sha256": DIGEST,
        "outcome": "reserved",
    }
    replay_nonce = {
        "schema": "1",
        "nonce": NONCE,
        "request_id": REQUEST_ID,
        "request_sha256": DIGEST,
        "outcome": "reserved",
    }
    terminal = {
        "schema": "1",
        "transaction": f"csr-{REQUEST_ID}",
        "request_id": REQUEST_ID,
        "operation": "issue",
        "service": "External_1",
        "outcome": "published",
        "committed": "true",
    }
    return (
        (CSR_REQUEST_FIELDS, _request_values(), parse_csr_request, serialize_csr_request),
        (CSR_APPROVAL_FIELDS, _approval_values(), parse_csr_approval, serialize_csr_approval),
        (CSR_RESPONSE_FIELDS, _response_values(), parse_csr_response, serialize_csr_response),
        (CSR_CANDIDATE_FIELDS, _candidate_values(), parse_csr_candidate, serialize_csr_candidate),
        (CSR_REPLAY_REQUEST_FIELDS, replay_request, parse_csr_replay_request, serialize_csr_replay_request),
        (CSR_REPLAY_NONCE_FIELDS, replay_nonce, parse_csr_replay_nonce, serialize_csr_replay_nonce),
        (CSR_TERMINAL_FIELDS, terminal, parse_csr_terminal, serialize_csr_terminal),
    )


def _shell_array(source: str, name: str) -> tuple[str, ...]:
    matches = tuple(
        re.finditer(
            rf"(?ms)^{re.escape(name)}=\((?P<body>.*?)\)(?:\n|$)", source
        )
    )
    assert matches
    bodies = tuple(tuple(match.group("body").split()) for match in matches)
    return next((body for body in reversed(bodies) if body), ())


def _literal_fields(source: str, start: str, end: str) -> tuple[str, ...]:
    body = source.split(start, 1)[1].split(end, 1)[0]
    fields = ["schema"]
    fields.extend(
        match.group(1)
        for line in body.splitlines()
        if (match := re.match(r"([a-z0-9_]+)=", line))
    )
    return tuple(fields)


def test_host_local_field_tuples_match_retained_shell_declarations() -> None:
    signing = (ROOT / "lib/platform-pki-csr-sign.sh").read_text(encoding="utf-8")
    candidate = (ROOT / "lib/platform-pki-csr-candidate.sh").read_text(encoding="utf-8")
    assert CSR_REQUEST_FIELDS == _shell_array(signing, "PKI_CSR_REQUEST_FIELDS")
    assert CSR_APPROVAL_FIELDS == _shell_array(signing, "PKI_CSR_APPROVAL_FIELDS")
    assert CSR_RESPONSE_FIELDS == _shell_array(candidate, "PKI_CANDIDATE_RESPONSE_FIELDS")
    assert CSR_CANDIDATE_FIELDS == _shell_array(candidate, "PKI_CANDIDATE_RECORD_FIELDS")
    assert CSR_REPLAY_REQUEST_FIELDS == _literal_fields(
        signing, 'content="schema=1\n', '\n"\n  pki_csr_ensure_replay_record'
    )
    assert CSR_REPLAY_NONCE_FIELDS == _literal_fields(
        signing.split('content="schema=1\n', 1)[1],
        'content="schema=1\n',
        '\n"\n  pki_csr_ensure_replay_record',
    )
    assert CSR_TERMINAL_FIELDS == _literal_fields(
        signing,
        'pki_atomic_write "$path" "schema=1\n',
        '\n"\n}',
    )


@pytest.mark.parametrize(
    "fields,values,parser,serializer", _record_cases(), ids=(
        "request", "approval", "response", "candidate", "replay-request", "replay-nonce", "terminal"
    )
)
def test_host_local_records_have_exact_counts_and_canonical_round_trips(
    fields, values, parser, serializer
) -> None:
    expected_counts = (15, 13, 22, 20, 9, 5, 7)
    assert len(fields) == expected_counts[[case[0] for case in _record_cases()].index(fields)]
    payload = _payload(fields, values)
    typed = parser(payload)
    assert typed.to_bytes() == payload
    assert serializer(typed) == payload
    assert serializer(dict(reversed(tuple(values.items())))) == payload


@pytest.mark.parametrize("mutation", ("duplicate", "unknown", "missing", "reordered", "empty", "control", "no-newline"))
def test_every_host_local_parser_rejects_noncanonical_structure(mutation: str) -> None:
    for fields, values, parser, _serializer in _record_cases():
        lines = _payload(fields, values).splitlines()
        if mutation == "duplicate":
            lines[-1] = lines[0]
        elif mutation == "unknown":
            lines[-1] = b"unknown=value"
        elif mutation == "missing":
            lines.pop()
        elif mutation == "reordered":
            lines[0], lines[1] = lines[1], lines[0]
        elif mutation == "empty":
            lines[-1] = lines[-1].partition(b"=")[0] + b"="
        elif mutation == "control":
            lines[-1] += b"\t"
        data = b"\n".join(lines) + (b"" if mutation == "no-newline" else b"\n")
        with pytest.raises(CsrProtocolError):
            parser(data)


def test_host_local_typed_bindings_and_operation_constraints() -> None:
    request = parse_csr_request(_payload(CSR_REQUEST_FIELDS, _request_values()))
    approval_values = _approval_values()
    approval = parse_csr_approval(_payload(CSR_APPROVAL_FIELDS, approval_values))
    validate_request_approval_binding(request, approval)
    approval_values["target"] = "host-02.example"
    with pytest.raises(CsrProtocolError, match="target"):
        validate_request_approval_binding(
            request, parse_csr_approval(_payload(CSR_APPROVAL_FIELDS, approval_values))
        )

    response = parse_csr_response(_payload(CSR_RESPONSE_FIELDS, _response_values()))
    candidate_values = _candidate_values()
    candidate = parse_csr_candidate(_payload(CSR_CANDIDATE_FIELDS, candidate_values))
    validate_response_candidate_binding(response, candidate)
    candidate_values["serial"] = "10B0"
    with pytest.raises(CsrProtocolError, match="serial"):
        validate_response_candidate_binding(
            response, parse_csr_candidate(_payload(CSR_CANDIDATE_FIELDS, candidate_values))
        )
    assert request.operation is CsrOperation.ISSUE


@pytest.mark.parametrize("serial", ("00", "01", "FF", "0100"))
@pytest.mark.parametrize("record", ("response", "candidate"))
def test_csr_serial_codecs_accept_canonical_boundaries(
    record: str, serial: str
) -> None:
    if record == "response":
        values = _response_values()
        values["serial"] = serial
        payload = _payload(CSR_RESPONSE_FIELDS, values)
        assert serialize_csr_response(parse_csr_response(payload)) == payload
    else:
        response = _response_values()
        response["serial"] = serial
        values = _candidate_values(response)
        payload = _payload(CSR_CANDIDATE_FIELDS, values)
        assert serialize_csr_candidate(parse_csr_candidate(payload)) == payload


@pytest.mark.parametrize("record", ("response", "candidate"))
def test_csr_serial_codecs_reject_zero_padded_leading_pair(record: str) -> None:
    if record == "response":
        fields = CSR_RESPONSE_FIELDS
        values = _response_values()
        parser = parse_csr_response
        serializer = serialize_csr_response
    else:
        fields = CSR_CANDIDATE_FIELDS
        values = _candidate_values()
        parser = parse_csr_candidate
        serializer = serialize_csr_candidate
    values["serial"] = "00AF"
    with pytest.raises(CsrProtocolError, match="serial"):
        parser(_payload(fields, values))
    with pytest.raises(CsrProtocolError, match="serial"):
        serializer(values)


def test_canonical_record_digest_bindings_match_retained_hash_behavior() -> None:
    request_values = _request_values()
    request_bytes = _payload(CSR_REQUEST_FIELDS, request_values)
    request = parse_csr_request(request_bytes)
    approval_values = _approval_values(request_values)
    assert approval_values["request_sha256"] == sha256(request_bytes).hexdigest()
    approval = parse_csr_approval(_payload(CSR_APPROVAL_FIELDS, approval_values))
    validate_request_approval_binding(request, approval)

    response_values = _response_values()
    response_bytes = _payload(CSR_RESPONSE_FIELDS, response_values)
    response = parse_csr_response(response_bytes)
    candidate_values = _candidate_values(response_values)
    assert candidate_values["response_sha256"] == sha256(response_bytes).hexdigest()
    candidate = parse_csr_candidate(
        _payload(CSR_CANDIDATE_FIELDS, candidate_values)
    )
    validate_response_candidate_binding(response, candidate)

    signing = (ROOT / "lib/platform-pki-csr-sign.sh").read_text(encoding="utf-8")
    candidate_source = (ROOT / "lib/platform-pki-csr-candidate.sh").read_text(
        encoding="utf-8"
    )
    assert 'CSR_REQUEST_SHA256=$(pki_csr_sha256 "$CSR_INPUT_DIR/request")' in signing
    assert '${CSR_APPROVAL[request_sha256]} == "$CSR_REQUEST_SHA256"' in signing
    assert 'CANDIDATE_RESPONSE_SHA256=$(pki_candidate_sha256 "$RESPONSE_DIR/response"' in candidate_source
    assert '${CANDIDATE_RECORD[response_sha256]} == "$CANDIDATE_RESPONSE_SHA256"' in candidate_source


@pytest.mark.parametrize("record", ("approval", "candidate"))
def test_canonical_record_digest_substitution_is_rejected(record: str) -> None:
    if record == "approval":
        request = parse_csr_request(
            _payload(CSR_REQUEST_FIELDS, _request_values())
        )
        values = _approval_values()
        values["request_sha256"] = "f" * 64
        approval = parse_csr_approval(_payload(CSR_APPROVAL_FIELDS, values))
        with pytest.raises(CsrProtocolError, match="canonical request bytes"):
            validate_request_approval_binding(request, approval)
    else:
        response = parse_csr_response(
            _payload(CSR_RESPONSE_FIELDS, _response_values())
        )
        values = _candidate_values()
        values["response_sha256"] = "f" * 64
        candidate = parse_csr_candidate(_payload(CSR_CANDIDATE_FIELDS, values))
        with pytest.raises(CsrProtocolError, match="canonical response bytes"):
            validate_response_candidate_binding(response, candidate)


@pytest.mark.parametrize(
    ("fields", "values", "parser", "digest_field"),
    (
        (CSR_APPROVAL_FIELDS, _approval_values(), parse_csr_approval, "request_sha256"),
        (CSR_CANDIDATE_FIELDS, _candidate_values(), parse_csr_candidate, "response_sha256"),
    ),
)
def test_cross_record_digest_syntax_remains_strict_lowercase(
    fields, values, parser, digest_field: str
) -> None:
    values[digest_field] = "A" * 64
    with pytest.raises(CsrProtocolError, match=digest_field):
        parser(_payload(fields, values))


def test_request_approval_timing_boundaries_match_retained_policy() -> None:
    request_values = _request_values()
    request_values.update(
        created_epoch="100",
        expires_epoch=str(100 + CSR_REQUEST_MAX_AGE_SECONDS),
    )
    approval_values = _approval_values(request_values)
    approval_values.update(
        created_epoch="100",
        expires_epoch=str(100 + CSR_APPROVAL_MAX_AGE_SECONDS),
    )
    request = parse_csr_request(_payload(CSR_REQUEST_FIELDS, request_values))
    approval = parse_csr_approval(_payload(CSR_APPROVAL_FIELDS, approval_values))
    assert serialize_csr_request(request) == _payload(
        CSR_REQUEST_FIELDS, request_values
    )
    assert serialize_csr_approval(approval) == _payload(
        CSR_APPROVAL_FIELDS, approval_values
    )
    validate_request_approval_binding(request, approval, signer_keys_match=False)

    approval_values.update(
        created_epoch=str(100 + CSR_SOLE_OPERATOR_MIN_DELAY_SECONDS),
        expires_epoch=str(101 + CSR_SOLE_OPERATOR_MIN_DELAY_SECONDS),
    )
    delayed = parse_csr_approval(_payload(CSR_APPROVAL_FIELDS, approval_values))
    validate_request_approval_binding(request, delayed, signer_keys_match=True)


@pytest.mark.parametrize("record", ("request", "approval"))
def test_standalone_request_and_approval_reject_overlong_intervals(
    record: str,
) -> None:
    if record == "request":
        fields = CSR_REQUEST_FIELDS
        values = _request_values()
        parser = parse_csr_request
        serializer = serialize_csr_request
        maximum = CSR_REQUEST_MAX_AGE_SECONDS
    else:
        fields = CSR_APPROVAL_FIELDS
        values = _approval_values()
        parser = parse_csr_approval
        serializer = serialize_csr_approval
        maximum = CSR_APPROVAL_MAX_AGE_SECONDS
    values["expires_epoch"] = str(int(values["created_epoch"]) + maximum + 1)
    with pytest.raises(CsrProtocolError, match="validity interval exceeds policy"):
        parser(_payload(fields, values))
    with pytest.raises(CsrProtocolError, match="validity interval exceeds policy"):
        serializer(values)


@pytest.mark.parametrize(
    ("case", "message"),
    (
        ("approval-predates-request", "predates"),
        ("sole-operator-too-soon", "sole-operator"),
    ),
)
def test_request_approval_timing_rejects_retained_policy_violations(
    case: str, message: str
) -> None:
    request_values = _request_values()
    approval_values = _approval_values()
    signer_keys_match = False
    if case == "approval-predates-request":
        approval_values.update(created_epoch="99", expires_epoch="100")
    else:
        approval_values.update(
            created_epoch=str(
                int(request_values["created_epoch"])
                + CSR_SOLE_OPERATOR_MIN_DELAY_SECONDS
                - 1
            ),
            expires_epoch=str(
                int(request_values["created_epoch"])
                + CSR_SOLE_OPERATOR_MIN_DELAY_SECONDS
            ),
        )
        signer_keys_match = True
    approval_values["request_sha256"] = sha256(
        _payload(CSR_REQUEST_FIELDS, request_values)
    ).hexdigest()
    request = parse_csr_request(_payload(CSR_REQUEST_FIELDS, request_values))
    approval = parse_csr_approval(_payload(CSR_APPROVAL_FIELDS, approval_values))
    with pytest.raises(CsrProtocolError, match=message):
        validate_request_approval_binding(
            request, approval, signer_keys_match=signer_keys_match
        )


def test_request_approval_timing_constants_are_source_backed() -> None:
    signing = (ROOT / "lib/platform-pki-csr-sign.sh").read_text(encoding="utf-8")
    function = signing.split("pki_csr_validate_times() {", 1)[1].split("\n}", 1)[0]
    assert "request_expires - request_created <= 604800" in function
    assert "approval_expires - approval_created <= 86400" in function
    assert "approval_created >= request_created" in function
    assert "approval_created - request_created >= 86400" in function


def _destination(key: str, *, service: str, intermediate: str, serial: str, archive: str) -> str:
    relative = {
        "service_root": f"services/{service}",
        "service_private_dir": f"services/{service}/private",
        "service_csr_dir": f"services/{service}/csr",
        "service_certs_dir": f"services/{service}/certs",
        "service_chain_dir": f"services/{service}/chain",
        "service_config": f"services/{service}/openssl.cnf",
        "service_csr": f"services/{service}/csr/tls.csr",
        "service_certificate": f"services/{service}/certs/tls.crt",
        "service_chain": f"services/{service}/chain/ca-chain.crt",
        "service_fullchain": f"services/{service}/chain/fullchain.crt",
        "service_issuer": f"services/{service}/issuer",
        "ca_index": f"authorities/intermediates/{intermediate}/index.txt",
        "ca_index_attr": f"authorities/intermediates/{intermediate}/index.txt.attr",
        "ca_serial": f"authorities/intermediates/{intermediate}/serial",
        "ca_index_old": f"authorities/intermediates/{intermediate}/index.txt.old",
        "ca_index_attr_old": f"authorities/intermediates/{intermediate}/index.txt.attr.old",
        "ca_serial_old": f"authorities/intermediates/{intermediate}/serial.old",
        "ca_newcert": f"authorities/intermediates/{intermediate}/newcerts/{serial}.pem",
        "service_key": f"services/{service}/private/tls.key",
        "archive_marker": f"services/{service}/archive/{archive}/.platform-pki-renew-archive",
        "archive_certificate": f"services/{service}/archive/{archive}/tls.crt",
        "archive_csr": f"services/{service}/archive/{archive}/tls.csr",
        "archive_chain": f"services/{service}/archive/{archive}/ca-chain.crt",
        "archive_fullchain": f"services/{service}/archive/{archive}/fullchain.crt",
        "archive_config": f"services/{service}/archive/{archive}/openssl.cnf",
        "archive_issuer": f"services/{service}/archive/{archive}/issuer",
        "archive_key": f"services/{service}/archive/{archive}/tls.key",
        "archive_root": f"services/{service}/archive",
        "archive_dir": f"services/{service}/archive/{archive}",
    }[key]
    return f"{PKI_DIR}/{relative}"


def _bind_journal_size(values: dict[str, str]) -> None:
    identity = values.get("journal_identity", "pending")
    if identity == "pending":
        inode = 9
        mode = 0o600
    else:
        fields = identity.split(":")
        inode = int(fields[1])
        mode = int(fields[3], 8)
    journal_size = 0
    while True:
        values["journal_identity"] = _object_identity(
            inode, mode=mode, size=journal_size
        )
        canonical_size = len(_payload(SERVICE_TRANSACTION_FIELDS, values))
        if canonical_size == journal_size:
            return
        journal_size = canonical_size


def _service_values(
    *,
    operation: ServiceOperation = ServiceOperation.ISSUE,
    key_action: ServiceKeyAction | None = None,
    archive_members: tuple[str, ...] | None = None,
    existing_archive_root: bool = False,
    existing_service_directories: tuple[str, ...] = SERVICE_CONTAINER_ORDER,
) -> dict[str, str]:
    if key_action is None:
        key_action = ServiceKeyAction.CREATE if operation is ServiceOperation.ISSUE else ServiceKeyAction.REUSE
    if operation is ServiceOperation.ISSUE:
        archive_state = ServiceArchiveState.ISSUE_KEY if key_action is ServiceKeyAction.ROTATE else ServiceArchiveState.NONE
        members = ("tls.key",) if archive_state is ServiceArchiveState.ISSUE_KEY else ()
    else:
        archive_state = ServiceArchiveState.RENEW
        members = archive_members or (".platform-pki-renew-archive", "issuer")
        if key_action is ServiceKeyAction.ROTATE and "tls.key" not in members:
            members = (*members, "tls.key")
    transaction = f"service-{REQUEST_ID}"
    transaction_dir = f"{PKI_DIR}/state/service/transactions/{transaction}"
    stage_dir = f"{transaction_dir}/stage"
    inputs_dir = f"{stage_dir}/inputs"
    backup_dir = f"{transaction_dir}/backup"
    archive = "20260811-120000" if archive_state is not ServiceArchiveState.NONE else "none"
    values = {field: "none" for field in SERVICE_TRANSACTION_FIELDS}
    values.update(
        schema="1",
        operation=operation.value,
        transaction=transaction,
        phase="planned",
        checkpoint="planned",
        mutation="none",
        committed="false",
        recovery_mode="rollback",
        outcome="none",
        service="app",
        issuer_root="g1",
        issuer_intermediate="g1-i1",
        serial="10AF",
        key_action=key_action.value,
        current_key_identity=("absent" if key_action is ServiceKeyAction.CREATE else _file_identity(10)),
        current_key_sha256=(
            "none"
            if key_action is ServiceKeyAction.CREATE
            else _evidence_digest("current-key")
        ),
        archive_state=archive_state.value,
        archive_name=archive,
        archive_members=(",".join(members) if members else "none"),
        owner=str(OWNER),
        created_epoch="100",
        staged_count="pending",
        backed_up_count="pending",
        published_count="0",
        rollback_count="0",
        rollback_completion_count="0",
        rollback_completion_path="none",
        rollback_completion_identity="none",
        rollback_completion_sha256="none",
        journal_path=f"{PKI_DIR}/{SERVICE_TRANSACTION_JOURNAL_RELATIVE_PATH}",
        journal_identity="pending",
        transaction_dir=transaction_dir,
        transaction_identity=DIRECTORY_IDENTITY,
        transaction_record_path=f"{transaction_dir}/transaction",
        transaction_record_identity="pending",
        transaction_record_sha256="pending",
        stage_dir=stage_dir,
        stage_dir_identity="1:3:1000:700:directory",
        inputs_dir=inputs_dir,
        inputs_dir_identity="1:5:1000:700:directory",
        backup_dir=backup_dir,
        backup_dir_identity="1:4:1000:700:directory",
        archive_root_snapshot_identity=(
            (_full_directory_identity(12) if existing_archive_root else "absent")
            if archive_state is not ServiceArchiveState.NONE
            else "none"
        ),
        archive_root_reference_path=(
            f"{transaction_dir}/archive-root-reference"
            if archive_state is not ServiceArchiveState.NONE and existing_archive_root
            else "none"
        ),
        archive_root_reference_identity=(
            _file_identity(13, size=0)
            if archive_state is not ServiceArchiveState.NONE and existing_archive_root
            else "none"
        ),
        archive_root_reference_sha256=(
            EMPTY_DIGEST
            if archive_state is not ServiceArchiveState.NONE and existing_archive_root
            else "none"
        ),
        archive_root_restored=(
            "false"
            if archive_state is not ServiceArchiveState.NONE and existing_archive_root
            else "none"
        ),
        archive_root_restored_identity="none",
        archive_marker_removed=(
            "false" if operation is ServiceOperation.RENEW else "none"
        ),
        stage_removed="false",
        backup_removed="false",
        terminal_path=f"{transaction_dir}/terminal",
        terminal_identity="none",
        terminal_sha256="none",
    )
    for index, key in enumerate(SERVICE_CONTAINER_ORDER):
        identity = _directory_identity(20 + index)
        values[f"{key}_destination"] = _destination(
            key,
            service="app",
            intermediate="g1-i1",
            serial="10AF",
            archive=archive,
        )
        values[f"{key}_pre_identity"] = (
            identity if key in existing_service_directories else "absent"
        )
        values[f"{key}_post_identity"] = (
            identity if key in existing_service_directories else "none"
        )
        values[f"{key}_rollback_identity"] = "none"
    created_service_directories = tuple(
        key
        for key in SERVICE_CONTAINER_ORDER
        if key not in existing_service_directories
    )
    if archive_state is not ServiceArchiveState.NONE:
        values["archive_root_destination"] = _destination(
            "archive_root",
            service="app",
            intermediate="g1-i1",
            serial="10AF",
            archive=archive,
        )
        values["archive_root_pre_identity"] = (
            _directory_identity(12) if existing_archive_root else "absent"
        )
        values["archive_root_post_identity"] = (
            _directory_identity(12) if existing_archive_root else "none"
        )
        values["archive_root_rollback_identity"] = "none"
        values["archive_dir_destination"] = _destination(
            "archive_dir",
            service="app",
            intermediate="g1-i1",
            serial="10AF",
            archive=archive,
        )
        values["archive_dir_pre_identity"] = "absent"
        values["archive_dir_post_identity"] = "none"
        values["archive_dir_rollback_identity"] = "none"
    order = managed_publication_order(
        operation,
        key_action,
        archive_state,
        members,
        create_archive_root=archive_state is not ServiceArchiveState.NONE and not existing_archive_root,
        created_service_directories=created_service_directories,
    )
    member_keys = {
        ".platform-pki-renew-archive": "archive_marker",
        "tls.crt": "archive_certificate",
        "tls.csr": "archive_csr",
        "ca-chain.crt": "archive_chain",
        "fullchain.crt": "archive_fullchain",
        "openssl.cnf": "archive_config",
        "issuer": "archive_issuer",
        "tls.key": "archive_key",
    }
    source_members = {
        member_keys[member]: member
        for member in members
        if member != ".platform-pki-renew-archive"
    }
    for archive_key, member in source_members.items():
        source_key = ARCHIVE_SOURCE_KEYS[archive_key]
        source_mode = {
            "service_certificate": 0o644,
            "service_csr": 0o600,
            "service_chain": 0o644,
            "service_fullchain": 0o644,
            "service_config": 0o600,
            "service_issuer": 0o600,
            "service_key": 0o600,
        }[source_key]
        values[f"{source_key}_pre_identity"] = (
            values["current_key_identity"]
            if source_key == "service_key"
            else _file_identity(
                50 + len(source_members) + len(member), mode=source_mode
            )
        )
    file_order = tuple(key for key in order if key not in SERVICE_CONTAINER_ORDER and key not in {"archive_root", "archive_dir"})
    fixed_modes = {
        "service_config": 0o600,
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
        "archive_marker": 0o600,
    }
    for index, key in enumerate(file_order):
        prefix = f"{key}_"
        pre = values[prefix + "pre_identity"]
        if pre == "none":
            pre = "absent"
        if key in {"ca_index", "ca_index_attr", "ca_serial"}:
            pre = _file_identity(20 + index)
        elif key == "service_key" and key_action is ServiceKeyAction.ROTATE:
            pre = values["current_key_identity"]
        values[prefix + "destination"] = _destination(
            key, service="app", intermediate="g1-i1", serial="10AF", archive=archive
        )
        values[prefix + "pre_identity"] = pre
        if pre != "absent":
            values[prefix + "pre_sha256"] = (
                values["current_key_sha256"]
                if key == "service_key"
                and key_action is ServiceKeyAction.ROTATE
                else _evidence_digest(f"pre:{key}")
            )
        values[prefix + "stage"] = f"{stage_dir}/{key}"
        if key == "archive_marker":
            values[prefix + "stage_identity"] = _file_identity(100 + index, mode=0o600, size=0)
            values[prefix + "stage_object"] = _object_identity(100 + index, mode=0o600, size=0)
            values[prefix + "stage_sha256"] = EMPTY_DIGEST
        elif key in source_members:
            source_key = ARCHIVE_SOURCE_KEYS[key]
            source_identity = values[f"{source_key}_pre_identity"]
            source_mode = int(source_identity.split(":", 4)[3], 8)
            values[prefix + "stage_identity"] = _file_identity(
                100 + index, mode=source_mode
            )
            values[prefix + "stage_object"] = _object_identity(
                100 + index, mode=source_mode
            )
            values[prefix + "source"] = values[f"{source_key}_destination"]
            values[prefix + "source_identity"] = source_identity
            values[prefix + "source_sha256"] = values[
                f"{source_key}_pre_sha256"
            ]
            values[prefix + "stage_sha256"] = values[
                f"{source_key}_pre_sha256"
            ]
        elif key in {"ca_index_old", "ca_index_attr_old", "ca_serial_old"}:
            source_key = {
                "ca_index_old": "ca_index",
                "ca_index_attr_old": "ca_index_attr",
                "ca_serial_old": "ca_serial",
            }[key]
            source_identity = values[f"{source_key}_pre_identity"]
            source_mode = int(source_identity.split(":", 4)[3], 8)
            source_size = int(source_identity.split(":", 6)[5])
            values[prefix + "stage_identity"] = _file_identity(
                100 + index, mode=source_mode, size=source_size
            )
            values[prefix + "stage_object"] = _object_identity(
                100 + index, mode=source_mode, size=source_size
            )
            values[prefix + "stage_sha256"] = values[f"{source_key}_pre_sha256"]
        elif key == "ca_newcert":
            certificate_identity = values["service_certificate_stage_identity"]
            certificate_size = int(certificate_identity.split(":", 6)[5])
            values[prefix + "stage_identity"] = _file_identity(
                100 + index, mode=0o600, size=certificate_size
            )
            values[prefix + "stage_object"] = _object_identity(
                100 + index, mode=0o600, size=certificate_size
            )
            values[prefix + "stage_sha256"] = values["service_certificate_stage_sha256"]
        elif key == "service_issuer":
            issuer_bytes = b"root=g1\nintermediate=g1-i1\n"
            values[prefix + "stage_identity"] = _file_identity(
                100 + index, mode=0o600, size=len(issuer_bytes)
            )
            values[prefix + "stage_object"] = _object_identity(
                100 + index, mode=0o600, size=len(issuer_bytes)
            )
            values[prefix + "stage_sha256"] = sha256(issuer_bytes).hexdigest()
        else:
            stage_mode = fixed_modes[key]
            values[prefix + "stage_identity"] = _file_identity(
                100 + index, mode=stage_mode
            )
            values[prefix + "stage_object"] = _object_identity(
                100 + index, mode=stage_mode
            )
            values[prefix + "stage_sha256"] = _evidence_digest(f"stage:{key}")
        if pre != "absent":
            pre_parts = pre.split(":", 5)
            pre_mode = int(pre_parts[3], 8)
            pre_size = int(pre_parts[5].split(":", 1)[0])
            values[prefix + "backup"] = f"{backup_dir}/{key}"
            values[prefix + "backup_identity"] = _file_identity(
                200 + index,
                mode=pre_mode,
                size=pre_size,
            )
            values[prefix + "backup_object"] = _object_identity(
                200 + index,
                mode=pre_mode,
                size=pre_size,
            )
            values[prefix + "backup_sha256"] = values[prefix + "pre_sha256"]
    signing_sources = {
        "signing_inventory": (
            f"{PKI_DIR}/inventory/services.yml",
            _file_identity(398, mode=0o640),
        ),
        "signing_root_certificate": (
            f"{PKI_DIR}/authorities/roots/g1/certs/root-ca.crt",
            _file_identity(399, mode=0o644),
        ),
        "signing_ca_key": (
            f"{PKI_DIR}/authorities/intermediates/g1-i1/private/intermediate-ca.key",
            _file_identity(400, mode=0o600),
        ),
        "signing_ca_certificate": (
            f"{PKI_DIR}/authorities/intermediates/g1-i1/certs/intermediate-ca.crt",
            _file_identity(401, mode=0o644),
        ),
        "signing_ca_config": (
            f"{PKI_DIR}/authorities/intermediates/g1-i1/openssl.cnf",
            _file_identity(402, mode=0o600),
        ),
        "signing_ca_crlnumber": (
            f"{PKI_DIR}/authorities/intermediates/g1-i1/crlnumber",
            _file_identity(403, mode=0o600),
        ),
    }
    if key_action is ServiceKeyAction.REUSE:
        signing_sources["signing_service_key"] = (
            f"{PKI_DIR}/services/app/private/tls.key",
            values["current_key_identity"],
        )
    for index, (key, (source, source_identity)) in enumerate(
        signing_sources.items()
    ):
        source_mode = int(source_identity.split(":", 4)[3], 8)
        source_size = int(source_identity.split(":", 6)[5])
        source_sha256 = (
            values["current_key_sha256"]
            if key == "signing_service_key"
            else _evidence_digest(f"source:{key}")
        )
        stage_mode = (
            0o600
            if key in {
                "signing_inventory",
                "signing_ca_config",
                "signing_service_key",
            }
            else source_mode
        )
        stage_sha256 = (
            _evidence_digest("stage:signing_ca_config")
            if key == "signing_ca_config"
            else source_sha256
        )
        values[f"{key}_source"] = source
        values[f"{key}_source_identity"] = source_identity
        values[f"{key}_source_sha256"] = source_sha256
        values[f"{key}_stage"] = f"{stage_dir}/inputs/{key}"
        values[f"{key}_stage_identity"] = _file_identity(
            500 + index,
            mode=stage_mode,
            size=source_size,
        )
        values[f"{key}_stage_object"] = _object_identity(
            500 + index,
            mode=stage_mode,
            size=source_size,
        )
        values[f"{key}_stage_sha256"] = stage_sha256
    retained = {
        "schema": "1",
        "transaction": transaction,
        "operation": operation.value,
        "service": "app",
        "issuer_root": "g1",
        "issuer_intermediate": "g1-i1",
        "serial": "10AF",
        "key_action": key_action.value,
        "archive_state": archive_state.value,
        "archive_name": archive,
        "archive_members": values["archive_members"],
        "owner": str(OWNER),
        "created_epoch": "100",
    }
    transaction_bytes = _payload(SERVICE_RETAINED_TRANSACTION_FIELDS, retained)
    values["transaction_record_sha256"] = sha256(transaction_bytes).hexdigest()
    values["transaction_record_identity"] = _file_identity(
        11, size=len(transaction_bytes)
    )
    values["staged_count"] = str(len(signing_sources) + len(file_order))
    values["backed_up_count"] = str(
        sum(
            values[f"{key}_pre_identity"] != "absent"
            for key in file_order
        )
    )
    _bind_journal_size(values)
    return values


def _order(values: dict[str, str]) -> tuple[str, ...]:
    members = (
        ()
        if values["archive_members"] == "none"
        else tuple(values["archive_members"].split(","))
    )
    return managed_publication_order(
        ServiceOperation(values["operation"]),
        ServiceKeyAction(values["key_action"]),
        ServiceArchiveState(values["archive_state"]),
        members,
        create_archive_root=values["archive_root_snapshot_identity"] == "absent",
        created_service_directories=tuple(
            key
            for key in SERVICE_CONTAINER_ORDER
            if values[f"{key}_pre_identity"] == "absent"
        ),
    )


def _staging_order(values: dict[str, str]) -> tuple[str, ...]:
    signing_inputs = tuple(
        key
        for key in SERVICE_SIGNING_INPUT_KEYS
        if key != "signing_service_key" or values["key_action"] == "reuse"
    )
    file_mutations = tuple(
        key
        for key in _order(values)
        if f"{key}_stage_identity" in values
    )
    return (*signing_inputs, *file_mutations)


def _backup_order(values: dict[str, str]) -> tuple[str, ...]:
    return tuple(
        key
        for key in _order(values)
        if f"{key}_backup_identity" in values
        and values[f"{key}_pre_identity"] != "absent"
    )


def _set_backup_prefix(values: dict[str, str], count: int) -> tuple[str, ...]:
    order = _backup_order(values)
    for key in order[count:]:
        values[f"{key}_backup_identity"] = "none"
        values[f"{key}_backup_object"] = "none"
        values[f"{key}_backup_sha256"] = "none"
    values["backed_up_count"] = str(count)
    return order


def _set_stage_prefix(values: dict[str, str], count: int) -> tuple[str, ...]:
    order = _staging_order(values)
    for key in order[count:]:
        values[f"{key}_stage_identity"] = "none"
        values[f"{key}_stage_object"] = "none"
        values[f"{key}_stage_sha256"] = "none"
    values["staged_count"] = str(count)
    _set_backup_prefix(values, 0)
    return order


def _set_post_prefix(values: dict[str, str], count: int) -> tuple[str, ...]:
    order = _order(values)
    for index, key in enumerate(order):
        if key in SERVICE_CONTAINER_ORDER:
            values[f"{key}_post_identity"] = (
                _directory_identity(300 + index) if index < count else "none"
            )
            continue
        if key in {"archive_root", "archive_dir"}:
            values[f"{key}_post_identity"] = (
                _directory_identity(300 + index) if index < count else "none"
            )
            continue
        values[f"{key}_post_identity"] = (
            values[f"{key}_stage_identity"] if index < count else "none"
        )
        values[f"{key}_post_sha256"] = (
            values[f"{key}_stage_sha256"] if index < count else "none"
        )
    values["published_count"] = str(count)
    return order


def _set_rollback_prefix(values: dict[str, str], count: int) -> tuple[str, ...]:
    order = managed_rollback_order(
        _order(values)[: int(values["published_count"])]
    )
    for index, key in enumerate(order):
        if index >= count:
            values[f"{key}_rollback_identity"] = "none"
            if f"{key}_rollback_sha256" in values:
                values[f"{key}_rollback_sha256"] = "none"
        elif values[f"{key}_pre_identity"] == "absent":
            values[f"{key}_rollback_identity"] = "absent"
            if f"{key}_rollback_sha256" in values:
                values[f"{key}_rollback_sha256"] = "none"
        else:
            values[f"{key}_rollback_identity"] = values[f"{key}_backup_identity"]
            values[f"{key}_rollback_sha256"] = values[f"{key}_backup_sha256"]
    values["rollback_count"] = str(count)
    return order


def _clear_rollback_evidence(values: dict[str, str]) -> None:
    values["rollback_count"] = "0"
    for key in _order(values):
        values[f"{key}_rollback_identity"] = "none"
        if f"{key}_rollback_sha256" in values:
            values[f"{key}_rollback_sha256"] = "none"


def _rollback_evidence_digest(
    values: dict[str, str], rollback_order: tuple[str, ...]
) -> str:
    lines = [
        "schema=1",
        f'transaction={values["transaction"]}',
        f'published_count={values["published_count"]}',
        f'archive_root_restored={values["archive_root_restored"]}',
        f'archive_root_restored_identity={values["archive_root_restored_identity"]}',
    ]
    for index, key in enumerate(rollback_order):
        pre_identity = values[f"{key}_pre_identity"]
        pre_sha256 = values.get(f"{key}_pre_sha256", "none")
        if pre_identity == "absent":
            restore_object = "absent"
            restore_sha256 = "none"
        else:
            restore_object = values[f"{key}_backup_object"]
            restore_sha256 = values[f"{key}_backup_sha256"]
        lines.extend(
            (
                f"rollback_{index}_key={key}",
                f"rollback_{index}_pre_identity={pre_identity}",
                f"rollback_{index}_pre_sha256={pre_sha256}",
                f"rollback_{index}_restore_object={restore_object}",
                f"rollback_{index}_restore_sha256={restore_sha256}",
            )
        )
    return sha256(("\n".join(lines) + "\n").encode("ascii")).hexdigest()


def _set_rollback_completion(
    values: dict[str, str], *, pending: bool = False
) -> bytes | None:
    rollback_order = managed_rollback_order(
        _order(values)[: int(values["published_count"])]
    )
    values["rollback_completion_path"] = (
        f'{values["transaction_dir"]}/rollback-complete'
    )
    if pending:
        values["rollback_completion_count"] = "0"
        values["rollback_completion_identity"] = "none"
        values["rollback_completion_sha256"] = "none"
        return None
    completion = {
        "schema": "1",
        "transaction": values["transaction"],
        "operation": values["operation"],
        "service": values["service"],
        "outcome": "failed-pre-commit",
        "published_count": values["published_count"],
        "completed_count": values["published_count"],
        "rollback_order": ",".join(rollback_order) if rollback_order else "none",
        "rollback_evidence_sha256": _rollback_evidence_digest(
            values, rollback_order
        ),
    }
    completion_bytes = serialize_service_retained_rollback(completion)
    values["rollback_completion_count"] = values["published_count"]
    values["rollback_completion_identity"] = _file_identity(
        910, size=len(completion_bytes)
    )
    values["rollback_completion_sha256"] = sha256(completion_bytes).hexdigest()
    return completion_bytes


def _set_terminal(values: dict[str, str]) -> None:
    terminal = {
        "schema": "1",
        "transaction": values["transaction"],
        "operation": values["operation"],
        "service": values["service"],
        "outcome": values["outcome"],
        "committed": values["committed"],
        "transaction_identity": values["transaction_record_identity"],
        "transaction_sha256": values["transaction_record_sha256"],
        "rollback_completion_identity": values["rollback_completion_identity"],
        "rollback_completion_sha256": values["rollback_completion_sha256"],
    }
    terminal_bytes = serialize_service_retained_terminal(terminal)
    values["terminal_identity"] = _file_identity(900, size=len(terminal_bytes))
    values["terminal_sha256"] = sha256(terminal_bytes).hexdigest()


def _set_service_serial(values: dict[str, str], serial: str) -> None:
    values["serial"] = serial
    values["ca_newcert_destination"] = _destination(
        "ca_newcert",
        service=values["service"],
        intermediate=values["issuer_intermediate"],
        serial=serial,
        archive=values["archive_name"],
    )
    retained = {
        field: values[field] for field in SERVICE_RETAINED_TRANSACTION_FIELDS
    }
    transaction_bytes = _payload(SERVICE_RETAINED_TRANSACTION_FIELDS, retained)
    values["transaction_record_sha256"] = sha256(transaction_bytes).hexdigest()
    values["transaction_record_identity"] = _file_identity(
        11, size=len(transaction_bytes)
    )


def _parse_values(values: dict[str, str], *, bind_journal: bool = True):
    if bind_journal:
        _bind_journal_size(values)
    return parse_service_transaction(
        _payload(SERVICE_TRANSACTION_FIELDS, values), pki_dir=PKI_DIR
    )


def test_managed_orders_and_lock_profile_are_backed_by_retained_sources() -> None:
    issue = (ROOT / "bashly/platform-pki-service-issue/src/root_command.sh").read_text(encoding="utf-8")
    renew = (ROOT / "bashly/platform-pki-service-renew/src/root_command.sh").read_text(encoding="utf-8")
    contract = (ROOT / "tests/pki/migration_contract.py").read_text(encoding="utf-8")
    expected = (
        "service_config", "service_csr", "service_certificate", "service_chain",
        "service_fullchain", "service_issuer", "ca_index", "ca_index_attr",
        "ca_serial", "ca_index_old", "ca_index_attr_old", "ca_serial_old", "ca_newcert",
    )
    assert SERVICE_CA_PUBLICATION_ORDER == expected
    assert MANAGED_ISSUE_PUBLICATION_ORDER == expected
    assert MANAGED_RENEW_PUBLICATION_ORDER == expected
    assert SERVICE_ISSUE_REPLACE_POLICY == tuple(
        value == "true" for value in _shell_array(issue, "TRANSACTION_REPLACE")
    )
    assert SERVICE_RENEW_REPLACE_POLICY == tuple(
        value == "true" for value in _shell_array(renew, "REPLACE")
    )
    assert SERVICE_ISSUE_REPLACE_POLICY == (
        True, True, False, True, True, False, True, True, True, True, True,
        True, False,
    )
    assert SERVICE_RENEW_REPLACE_POLICY == (
        True, True, True, True, True, True, True, True, True, True, True,
        True, False,
    )
    assert 'for ((i = ${#TRANSACTION_DESTINATIONS[@]} - 1; i >= 0; i--)); do' in issue
    assert 'for ((i = ${#DESTINATIONS[@]} - 1; i >= 0; i--)); do' in renew
    assert 'cp -p -- "$destination" "$backup"' in issue
    assert 'ln -- "$backup" "$destination"' in issue
    assert 'cp -p -- "$destination" "$backup"' in renew
    assert 'ln -- "${BACKUPS[i]}" "$destination"' in renew
    for source in (issue, renew):
        assert 'pki_load_inventory_snapshot "$INVENTORY_TMP_DIR"' in source
        assert 'cp -p -- "$INT_KEY" "$STAGE_INT_DIR/private/intermediate-ca.key"' in source
        assert 'cp -p -- "$INT_CERT" "$STAGE_INT_DIR/certs/intermediate-ca.crt"' in source
        assert 'index.txt index.txt.attr serial crlnumber' in source
        assert 'process_intermediate_signing_config "$INT_CONF" "$STAGE_INT_DIR/openssl.cnf"' in source
        assert 'chmod 600 "$STAGE_INT_DIR/openssl.cnf"' in source
        assert 'cp -p -- "$KEY" "$STAGE_KEY"' in source
        assert 'chmod 600 "$STAGE_KEY"' in source
        assert 'cat "$INT_CERT" "$ROOT_CERT" >"$STAGE_CHAIN"' in source
        assert "umask 077" in source
    service_directory_loop = (
        'for dir in "$SERVICE_DIR" "$SERVICE_DIR/private" "$SERVICE_DIR/csr" '
        '"$SERVICE_DIR/certs" "$SERVICE_DIR/chain"; do'
    )
    assert service_directory_loop in issue
    assert service_directory_loop in renew
    assert SERVICE_CONTAINER_ORDER == (
        "service_root",
        "service_private_dir",
        "service_csr_dir",
        "service_certs_dir",
        "service_chain_dir",
    )
    assert MANAGED_ISSUE_ARCHIVE_MEMBER_ORDER == ("tls.key",)
    assert 'TRANSACTION_DESTINATIONS+=("$ARCHIVE_DIR/tls.key")' in issue
    assert 'cp -p -- "$KEY" "$STAGE_SERVICE_DIR/archived-tls.key"' in issue
    assert MANAGED_RENEW_ARCHIVE_MEMBER_ORDER == (
        ".platform-pki-renew-archive", "tls.crt", "tls.csr", "ca-chain.crt",
        "fullchain.crt", "openssl.cnf", "issuer", "tls.key",
    )
    archive_candidates = re.search(
        r'(?m)^\s*archive_candidates=\((?P<body>[^\n]+)\)$', renew
    )
    assert archive_candidates is not None
    assert re.findall(r'"\$([A-Z_]+)\|([^"|]+)"', archive_candidates["body"]) == [
        ("CERT", "tls.crt"),
        ("CSR", "tls.csr"),
        ("CHAIN", "ca-chain.crt"),
        ("FULLCHAIN", "fullchain.crt"),
        ("CONF", "openssl.cnf"),
        ("ISSUER", "issuer"),
    ]
    assert 'archive_candidates+=("$KEY|tls.key")' in renew
    assert '[[ -e ${specification%%|*} ]] || continue' in renew
    assert 'cp -p -- "${ARCHIVE_SOURCES[i]}" "$STAGE_ARCHIVE_DIR/${ARCHIVE_NAMES[i]}"' in renew
    assert len(SERVICE_CONTINUITY_KEYS) == len(set(SERVICE_CONTINUITY_KEYS)) == 29
    assert set(SERVICE_CONTINUITY_KEYS) == {
        *SERVICE_CONTAINER_ORDER,
        *SERVICE_CA_PUBLICATION_ORDER,
        "service_key",
        "archive_root",
        "archive_dir",
        "archive_marker",
        "archive_certificate",
        "archive_csr",
        "archive_chain",
        "archive_fullchain",
        "archive_config",
        "archive_issuer",
        "archive_key",
    }
    assert not any(
        key.startswith(("root_", "intermediate_", "inventory_"))
        for key in SERVICE_CONTINUITY_KEYS
    )
    assert 'DESTINATIONS+=("$ARCHIVE_MARKER")' in renew
    assert SERVICE_TRANSACTION_LOCK_PROFILE == ("lifecycle", "root", "intermediate", "inventory")
    assert '_locks(LOCK_ORDER[:4])' in contract


@pytest.mark.parametrize(
    ("operation", "outcome", "expected"),
    (
        (ServiceOperation.ISSUE, ServiceOutcome.FAILED_PRE_COMMIT, ("stage", "backup")),
        (ServiceOperation.RENEW, ServiceOutcome.FAILED_PRE_COMMIT, ("stage", "backup")),
        (ServiceOperation.ISSUE, ServiceOutcome.SUCCEEDED, ("stage", "backup")),
        (
            ServiceOperation.RENEW,
            ServiceOutcome.SUCCEEDED,
            ("archive-marker", "stage", "backup"),
        ),
    ),
)
def test_service_cleanup_owned_set_is_complete_and_outcome_specific(
    operation: ServiceOperation,
    outcome: ServiceOutcome,
    expected: tuple[str, ...],
) -> None:
    assert SERVICE_CLEANUP_OWNED_KEYS == ("archive-marker", "stage", "backup")
    assert service_cleanup_owned_keys(operation, outcome) == expected


def test_service_journal_has_fixed_unique_fields_and_canonical_round_trip() -> None:
    values = _service_values()
    payload = _payload(SERVICE_TRANSACTION_FIELDS, values)
    journal = _parse_values(values)
    assert len(SERVICE_TRANSACTION_FIELDS) == 485
    assert len(SERVICE_TRANSACTION_FIELDS) == len(set(SERVICE_TRANSACTION_FIELDS))
    assert journal.to_bytes() == payload
    assert serialize_service_transaction(journal, pki_dir=PKI_DIR) == payload
    assert serialize_service_transaction(
        dict(reversed(tuple(values.items()))), pki_dir=PKI_DIR
    ) == payload
    assert isinstance(journal.identity("transaction_identity"), DirectoryIdentity)
    assert isinstance(journal.identity("journal_identity"), FileObjectState)
    assert isinstance(journal.identity("inputs_dir_identity"), DirectoryIdentity)
    assert isinstance(journal.identity("transaction_record_identity"), FileIdentity)
    assert journal.identity("current_key_identity") is IdentitySentinel.ABSENT
    assert all(
        isinstance(mutation.stage_object, FileObjectState)
        for mutation in journal.mutations
        if mutation.stage is not None
    )
    assert tuple(
        mutation.replace
        for mutation in journal.mutations
        if mutation.key in SERVICE_CA_PUBLICATION_ORDER
    ) == SERVICE_ISSUE_REPLACE_POLICY

    renew = _parse_values(_service_values(operation=ServiceOperation.RENEW))
    assert tuple(
        mutation.replace
        for mutation in renew.mutations
        if mutation.key in SERVICE_CA_PUBLICATION_ORDER
    ) == SERVICE_RENEW_REPLACE_POLICY


@pytest.mark.parametrize("serial", ("00", "01", "FF", "0100"))
def test_service_transaction_accepts_canonical_serial_boundaries(
    serial: str,
) -> None:
    values = _service_values()
    _set_service_serial(values, serial)
    journal = _parse_values(values)
    assert journal["serial"] == serial
    assert journal["ca_newcert_destination"].endswith(
        f"/newcerts/{serial}.pem"
    )


def test_service_transaction_rejects_zero_padded_serial_and_bound_path() -> None:
    values = _service_values()
    _set_service_serial(values, "00AF")
    with pytest.raises(ServiceTransactionError, match="serial"):
        _parse_values(values)


@pytest.mark.parametrize(
    ("operation", "key_action", "archive_state", "archive_name", "members"),
    (
        ("service-issue", "create", "none", "none", "none"),
        (
            "service-renew",
            "reuse",
            "renew",
            "20260811-120000",
            ".platform-pki-renew-archive,issuer",
        ),
    ),
)
def test_retained_transaction_and_terminal_records_have_canonical_bytes(
    operation: str,
    key_action: str,
    archive_state: str,
    archive_name: str,
    members: str,
) -> None:
    transaction = {
        "schema": "1",
        "transaction": f"service-{REQUEST_ID}",
        "operation": operation,
        "service": "app",
        "issuer_root": "g1",
        "issuer_intermediate": "g1-i1",
        "serial": "10AF",
        "key_action": key_action,
        "archive_state": archive_state,
        "archive_name": archive_name,
        "archive_members": members,
        "owner": str(OWNER),
        "created_epoch": "100",
    }
    transaction_bytes = _payload(SERVICE_RETAINED_TRANSACTION_FIELDS, transaction)
    parsed_transaction = parse_service_retained_transaction(transaction_bytes)
    assert parsed_transaction.to_bytes() == transaction_bytes
    assert serialize_service_retained_transaction(parsed_transaction) == transaction_bytes

    terminal = {
        "schema": "1",
        "transaction": transaction["transaction"],
        "operation": operation,
        "service": "app",
        "outcome": "succeeded",
        "committed": "true",
        "transaction_identity": _file_identity(
            11, size=len(transaction_bytes)
        ),
        "transaction_sha256": sha256(transaction_bytes).hexdigest(),
        "rollback_completion_identity": "none",
        "rollback_completion_sha256": "none",
    }
    terminal_bytes = _payload(SERVICE_RETAINED_TERMINAL_FIELDS, terminal)
    parsed_terminal = parse_service_retained_terminal(terminal_bytes)
    assert parsed_terminal.to_bytes() == terminal_bytes
    assert serialize_service_retained_terminal(parsed_terminal) == terminal_bytes
    rollback = {
        "schema": "1",
        "transaction": transaction["transaction"],
        "operation": operation,
        "service": "app",
        "outcome": "failed-pre-commit",
        "published_count": "0",
        "completed_count": "0",
        "rollback_order": "none",
        "rollback_evidence_sha256": DIGEST,
    }
    rollback_bytes = _payload(SERVICE_RETAINED_ROLLBACK_FIELDS, rollback)
    parsed_rollback = parse_service_retained_rollback(rollback_bytes)
    assert parsed_rollback.to_bytes() == rollback_bytes
    assert serialize_service_retained_rollback(parsed_rollback) == rollback_bytes
    assert len(SERVICE_RETAINED_TRANSACTION_FIELDS) == 13
    assert len(SERVICE_RETAINED_TERMINAL_FIELDS) == 10
    assert len(SERVICE_RETAINED_ROLLBACK_FIELDS) == 9


def test_retained_terminal_requires_outcome_specific_rollback_binding() -> None:
    transaction_identity = _file_identity(11, size=100)
    terminal = {
        "schema": "1",
        "transaction": f"service-{REQUEST_ID}",
        "operation": "service-issue",
        "service": "app",
        "outcome": "succeeded",
        "committed": "true",
        "transaction_identity": transaction_identity,
        "transaction_sha256": DIGEST,
        "rollback_completion_identity": "none",
        "rollback_completion_sha256": "none",
    }
    terminal["rollback_completion_identity"] = _file_identity(12, size=100)
    terminal["rollback_completion_sha256"] = DIGEST
    with pytest.raises(ServiceTransactionError, match="unexpected rollback"):
        serialize_service_retained_terminal(terminal)

    terminal.update(
        outcome="failed-pre-commit",
        committed="false",
        rollback_completion_identity="none",
        rollback_completion_sha256="none",
    )
    with pytest.raises(ServiceTransactionError, match="rollback evidence is incomplete"):
        serialize_service_retained_terminal(terminal)


@pytest.mark.parametrize(
    "field", ("transaction_identity", "rollback_completion_identity")
)
def test_retained_terminal_requires_safe_bound_file_identities(field: str) -> None:
    terminal = {
        "schema": "1",
        "transaction": f"service-{REQUEST_ID}",
        "operation": "service-issue",
        "service": "app",
        "outcome": "failed-pre-commit",
        "committed": "false",
        "transaction_identity": _file_identity(11, size=100),
        "transaction_sha256": DIGEST,
        "rollback_completion_identity": _file_identity(12, size=100),
        "rollback_completion_sha256": DIGEST,
    }
    terminal[field] = _file_identity(99, mode=0o644, size=100)
    with pytest.raises(ServiceTransactionError, match="identity is unsafe"):
        serialize_service_retained_terminal(terminal)


@pytest.mark.parametrize(
    ("key_action", "members", "message"),
    (
        ("reuse", "issuer", "archive lacks its marker"),
        (
            "reuse",
            ".platform-pki-renew-archive,issuer,tls.key",
            "key archive conflicts",
        ),
        (
            "rotate",
            ".platform-pki-renew-archive,issuer",
            "key archive conflicts",
        ),
    ),
)
def test_retained_renewal_requires_canonical_marker_and_key_archive(
    key_action: str, members: str, message: str
) -> None:
    values = {
        "schema": "1",
        "transaction": f"service-{REQUEST_ID}",
        "operation": "service-renew",
        "service": "app",
        "issuer_root": "g1",
        "issuer_intermediate": "g1-i1",
        "serial": "10AF",
        "key_action": key_action,
        "archive_state": "renew",
        "archive_name": "20260811-120000",
        "archive_members": members,
        "owner": str(OWNER),
        "created_epoch": "100",
    }
    with pytest.raises(ServiceTransactionError, match=message):
        parse_service_retained_transaction(
            _payload(SERVICE_RETAINED_TRANSACTION_FIELDS, values)
        )


@pytest.mark.parametrize("record", ("transaction", "terminal"))
def test_retained_record_identity_size_binds_canonical_bytes(record: str) -> None:
    values = _committed_values() if record == "terminal" else _service_values()
    if record == "terminal":
        values.update(phase="terminal", checkpoint="journal-cleanup-pending")
        _set_cleanup(values, "journal-cleanup-pending", renew=False)
        values["terminal_identity"] = _file_identity(900, size=1)
    else:
        values["transaction_record_identity"] = _file_identity(11, size=1)
    with pytest.raises(ServiceTransactionError, match="identity.*canonical bytes"):
        _parse_values(values)


def test_journal_object_state_size_binds_canonical_bytes() -> None:
    values = _service_values()
    identity = values["journal_identity"].split(":")
    values["journal_identity"] = _object_identity(
        int(identity[1]), size=int(identity[5]) + 1
    )
    with pytest.raises(ServiceTransactionError, match="journal object state"):
        _parse_values(values, bind_journal=False)


@pytest.mark.parametrize("field", ("transaction", "operation", "service"))
def test_transaction_record_digest_rejects_canonical_record_substitution(
    field: str,
) -> None:
    values = _service_values()
    retained = {
        key: values[key]
        for key in SERVICE_RETAINED_TRANSACTION_FIELDS
        if key != "schema"
    }
    retained["schema"] = "1"
    retained[field] = {
        "transaction": "service-ffffffffffffffffffffffffffffffff",
        "operation": "service-renew",
        "service": "other",
    }[field]
    values["transaction_record_sha256"] = sha256(
        _payload(SERVICE_RETAINED_TRANSACTION_FIELDS, retained)
    ).hexdigest()
    with pytest.raises(ServiceTransactionError, match="canonical bytes"):
        _parse_values(values)


def _assert_complete_mutation_authenticity(journal) -> None:
    for mutation in journal.mutations:
        if mutation.stage is None:
            assert mutation.pre_sha256 is None
            assert mutation.backup is None
            assert mutation.backup_identity is IdentitySentinel.NONE
            assert mutation.backup_object is IdentitySentinel.NONE
            assert mutation.backup_sha256 is None
            assert mutation.rollback_identity is IdentitySentinel.NONE
            continue
        assert isinstance(mutation.stage_identity, FileIdentity)
        assert isinstance(mutation.stage_object, FileObjectState)
        assert mutation.stage_identity.state == mutation.stage_object
        assert mutation.stage_sha256 is not None
        if mutation.pre_identity is IdentitySentinel.ABSENT:
            assert mutation.pre_sha256 is None
            assert mutation.backup is None
            assert mutation.backup_identity is IdentitySentinel.NONE
            assert mutation.backup_object is IdentitySentinel.NONE
            assert mutation.backup_sha256 is None
        else:
            assert isinstance(mutation.pre_identity, FileIdentity)
            assert mutation.pre_sha256 is not None
            assert mutation.backup is not None
            assert isinstance(mutation.backup_identity, FileIdentity)
            assert isinstance(mutation.backup_object, FileObjectState)
            assert mutation.backup_identity.state == mutation.backup_object
            assert mutation.backup_sha256 == mutation.pre_sha256
            assert (
                mutation.backup_identity.dev,
                mutation.backup_identity.ino,
            ) != (mutation.pre_identity.dev, mutation.pre_identity.ino)
        assert mutation.post_identity is IdentitySentinel.NONE
        assert mutation.post_sha256 is None
        assert mutation.rollback_identity is IdentitySentinel.NONE
        assert mutation.rollback_sha256 is None


@pytest.mark.parametrize(
    ("operation", "key_action", "archive_members"),
    (
        (ServiceOperation.ISSUE, ServiceKeyAction.REUSE, None),
        (ServiceOperation.ISSUE, ServiceKeyAction.CREATE, None),
        (ServiceOperation.ISSUE, ServiceKeyAction.ROTATE, None),
        (
            ServiceOperation.RENEW,
            ServiceKeyAction.REUSE,
            (".platform-pki-renew-archive",),
        ),
        (
            ServiceOperation.RENEW,
            ServiceKeyAction.REUSE,
            MANAGED_RENEW_ARCHIVE_MEMBER_ORDER[:-1],
        ),
        (
            ServiceOperation.RENEW,
            ServiceKeyAction.ROTATE,
            MANAGED_RENEW_ARCHIVE_MEMBER_ORDER[:-1],
        ),
    ),
)
def test_issue_renew_key_and_archive_variants_have_complete_authenticity_chains(
    operation: ServiceOperation,
    key_action: ServiceKeyAction,
    archive_members: tuple[str, ...] | None,
) -> None:
    values = _service_values(
        operation=operation,
        key_action=key_action,
        archive_members=archive_members,
    )
    journal = _parse_values(values)
    _assert_complete_mutation_authenticity(journal)

    order = _order(values)
    _set_post_prefix(values, len(order))
    rollback = _set_rollback_prefix(values, len(order))
    values.update(
        phase="rolling-back",
        checkpoint="rollback-done",
        mutation=rollback[-1],
        outcome="failed-pre-commit",
    )
    restored = _parse_values(values)
    for mutation in restored.mutations:
        if mutation.key not in order:
            continue
        if mutation.pre_identity is IdentitySentinel.ABSENT:
            assert mutation.rollback_identity is IdentitySentinel.ABSENT
            assert mutation.rollback_sha256 is None
        else:
            assert isinstance(mutation.rollback_identity, FileIdentity)
            assert mutation.rollback_identity.state == mutation.backup_object
            assert mutation.rollback_sha256 == mutation.pre_sha256
            assert mutation.rollback_sha256 == mutation.backup_sha256

    _set_rollback_completion(values)
    _clear_rollback_evidence(values)
    values.update(
        phase="cleaning-up",
        checkpoint="cleanup-stage-pending",
        mutation="none",
        recovery_mode="cleanup-only",
        outcome="failed-pre-commit",
    )
    restored = _parse_values(values)
    for mutation in restored.mutations:
        assert mutation.rollback_identity is IdentitySentinel.NONE
        assert mutation.rollback_sha256 is None


def test_writer_derived_stage_and_archive_mode_matrix_is_exact() -> None:
    issue = _parse_values(_service_values())
    issue_mutations = {mutation.key: mutation for mutation in issue.mutations}
    expected_issue_modes = {
        "service_config": 0o600,
        "service_csr": 0o600,
        "service_certificate": 0o644,
        "service_chain": 0o644,
        "service_fullchain": 0o644,
        "service_issuer": 0o600,
        "ca_index": 0o600,
        "ca_index_attr": 0o600,
        "ca_serial": 0o600,
        "ca_index_old": 0o600,
        "ca_index_attr_old": 0o600,
        "ca_serial_old": 0o600,
        "ca_newcert": 0o600,
        "service_key": 0o600,
    }
    actual_issue_modes = {}
    for key in expected_issue_modes:
        identity = issue_mutations[key].stage_identity
        assert isinstance(identity, FileIdentity)
        actual_issue_modes[key] = identity.permissions
    assert actual_issue_modes == expected_issue_modes

    renew = _parse_values(
        _service_values(
            operation=ServiceOperation.RENEW,
            archive_members=MANAGED_RENEW_ARCHIVE_MEMBER_ORDER[:-1],
        )
    )
    renew_mutations = {mutation.key: mutation for mutation in renew.mutations}
    expected_archive_modes = {
        "archive_marker": 0o600,
        "archive_certificate": 0o644,
        "archive_csr": 0o600,
        "archive_chain": 0o644,
        "archive_fullchain": 0o644,
        "archive_config": 0o600,
        "archive_issuer": 0o600,
    }
    actual_archive_modes = {}
    for key in expected_archive_modes:
        identity = renew_mutations[key].stage_identity
        assert isinstance(identity, FileIdentity)
        actual_archive_modes[key] = identity.permissions
    assert actual_archive_modes == expected_archive_modes


@pytest.mark.parametrize(
    ("key_action", "expected_keys"),
    (
        (
            ServiceKeyAction.CREATE,
            SERVICE_SIGNING_INPUT_KEYS[:-1],
        ),
        (
            ServiceKeyAction.ROTATE,
            SERVICE_SIGNING_INPUT_KEYS[:-1],
        ),
        (ServiceKeyAction.REUSE, SERVICE_SIGNING_INPUT_KEYS),
    ),
)
def test_private_signing_inputs_cover_every_retained_stage_copy(
    key_action: ServiceKeyAction,
    expected_keys: tuple[str, ...],
) -> None:
    journal = _parse_values(_service_values(key_action=key_action))
    assert tuple(item.key for item in journal.signing_inputs) == expected_keys
    for item in journal.signing_inputs:
        assert isinstance(item.stage_identity, FileIdentity)
        assert isinstance(item.stage_object, FileObjectState)
        assert item.stage_identity.state == item.stage_object
        assert (item.stage_identity.dev, item.stage_identity.ino) != (
            item.source_identity.dev,
            item.source_identity.ino,
        )
        if item.key != "signing_ca_config":
            assert item.stage_sha256 == item.source_sha256
        if item.key in {
            "signing_root_certificate",
            "signing_ca_key",
            "signing_ca_certificate",
            "signing_ca_crlnumber",
        }:
            assert item.stage_identity.permissions == item.source_identity.permissions
            assert item.stage_identity.mtime_ns == item.source_identity.mtime_ns
        else:
            assert item.stage_identity.permissions == 0o600


def test_transaction_inputs_bind_inventory_and_complete_certificate_chain() -> None:
    journal = _parse_values(_service_values())
    inputs = {item.key: item for item in journal.signing_inputs}
    assert tuple(inputs) == SERVICE_SIGNING_INPUT_KEYS[:-1]
    inventory = inputs["signing_inventory"]
    assert inventory.source == (
        f"{PKI_DIR}/inventory/services.yml"
    )
    assert isinstance(inventory.stage_identity, FileIdentity)
    assert inventory.stage_identity.permissions == 0o600
    assert inputs["signing_root_certificate"].source == (
        f"{PKI_DIR}/authorities/roots/g1/certs/root-ca.crt"
    )
    assert (
        inputs["signing_root_certificate"].stage_sha256
        == inputs["signing_root_certificate"].source_sha256
    )


def test_writer_preserved_modes_remain_exact_for_safe_sources() -> None:
    values = _service_values(
        operation=ServiceOperation.RENEW,
        archive_members=MANAGED_RENEW_ARCHIVE_MEMBER_ORDER[:-1],
    )
    values["service_certificate_pre_identity"] = _file_identity(70, mode=0o640)
    values["service_certificate_backup_identity"] = _file_identity(207, mode=0o640)
    values["service_certificate_backup_object"] = _object_identity(207, mode=0o640)
    values["archive_certificate_source_identity"] = values[
        "service_certificate_pre_identity"
    ]
    values["archive_certificate_stage_identity"] = _file_identity(117, mode=0o640)
    values["archive_certificate_stage_object"] = _object_identity(117, mode=0o640)
    journal = _parse_values(values)
    archived = {mutation.key: mutation for mutation in journal.mutations}[
        "archive_certificate"
    ]
    assert isinstance(archived.stage_identity, FileIdentity)
    assert archived.stage_identity.permissions == 0o640

    values = _service_values(key_action=ServiceKeyAction.ROTATE)
    strict_key = _file_identity(10, mode=0o400)
    values["current_key_identity"] = strict_key
    values["service_key_pre_identity"] = strict_key
    values["service_key_backup_identity"] = _file_identity(213, mode=0o400)
    values["service_key_backup_object"] = _object_identity(213, mode=0o400)
    values["archive_key_source_identity"] = strict_key
    values["archive_key_stage_identity"] = _file_identity(114, mode=0o400)
    values["archive_key_stage_object"] = _object_identity(114, mode=0o400)
    journal = _parse_values(values)
    archived_key = {mutation.key: mutation for mutation in journal.mutations}[
        "archive_key"
    ]
    assert isinstance(archived_key.stage_identity, FileIdentity)
    assert archived_key.stage_identity.permissions == 0o400

    values = _service_values(key_action=ServiceKeyAction.REUSE)
    strict_key = _file_identity(10, mode=0o400)
    values["current_key_identity"] = strict_key
    values["signing_service_key_source_identity"] = strict_key
    reused = _parse_values(values).signing_inputs[-1]
    assert reused.source_identity.permissions == 0o400
    assert isinstance(reused.stage_identity, FileIdentity)
    assert reused.stage_identity.permissions == 0o600

    values = _service_values()
    values["service_root_pre_identity"] = _directory_identity(20, mode=0o750)
    values["service_root_post_identity"] = _directory_identity(20, mode=0o750)
    service_root = _parse_values(values).mutations[0].pre_identity
    assert isinstance(service_root, DirectoryIdentity)
    assert service_root.permissions == 0o750

    values = _service_values(
        operation=ServiceOperation.RENEW,
        existing_archive_root=True,
    )
    values["archive_root_snapshot_identity"] = _full_directory_identity(
        12, mode=0o750
    )
    values["archive_root_pre_identity"] = _directory_identity(12, mode=0o750)
    values["archive_root_post_identity"] = _directory_identity(12, mode=0o750)
    archive_root = {
        mutation.key: mutation for mutation in _parse_values(values).mutations
    }["archive_root"]
    assert isinstance(archive_root.pre_identity, DirectoryIdentity)
    assert archive_root.pre_identity.permissions == 0o750


@pytest.mark.parametrize(
    "case",
    (
        "key-stage-public",
        "certificate-stage-private",
        "ca-stage-preserved",
        "archive-marker-public",
        "current-key-public",
        "ca-pre-public",
        "public-pre-writable",
        "backup-mode-change",
        "publication-mode-change",
        "journal-mode",
        "transaction-record-mode",
        "stage-directory-mode",
        "inputs-directory-mode",
        "backup-directory-mode",
        "existing-container-writable",
        "created-container-noncanonical",
    ),
)
def test_mode_matrix_rejects_every_unsafe_or_non_writer_mode(case: str) -> None:
    values = _service_values()
    if case == "key-stage-public":
        values["service_key_stage_identity"] = _file_identity(113, mode=0o644)
        values["service_key_stage_object"] = _object_identity(113, mode=0o644)
    elif case == "certificate-stage-private":
        values["service_certificate_stage_identity"] = _file_identity(102, mode=0o600)
        values["service_certificate_stage_object"] = _object_identity(102, mode=0o600)
    elif case == "ca-stage-preserved":
        values["ca_index_stage_identity"] = _file_identity(106, mode=0o400)
        values["ca_index_stage_object"] = _object_identity(106, mode=0o400)
    elif case == "archive-marker-public":
        values = _service_values(operation=ServiceOperation.RENEW)
        values["archive_marker_stage_identity"] = _file_identity(113, mode=0o644, size=0)
        values["archive_marker_stage_object"] = _object_identity(113, mode=0o644, size=0)
    elif case == "current-key-public":
        values = _service_values(key_action=ServiceKeyAction.REUSE)
        values["current_key_identity"] = _file_identity(10, mode=0o644)
    elif case == "ca-pre-public":
        values["ca_index_pre_identity"] = _file_identity(26, mode=0o644)
    elif case == "public-pre-writable":
        values = _service_values(
            operation=ServiceOperation.RENEW,
            archive_members=(".platform-pki-renew-archive", "tls.crt"),
        )
        values["service_certificate_pre_identity"] = _file_identity(70, mode=0o666)
    elif case == "backup-mode-change":
        values["ca_index_backup_identity"] = _file_identity(206, mode=0o400)
        values["ca_index_backup_object"] = _object_identity(206, mode=0o400)
    elif case == "publication-mode-change":
        _set_post_prefix(values, 1)
        values["service_config_post_identity"] = _file_identity(100, mode=0o400)
        values.update(
            phase="publishing",
            checkpoint="publication-done",
            mutation="service_config",
        )
    elif case == "journal-mode":
        size = int(values["journal_identity"].split(":")[5])
        values["journal_identity"] = _object_identity(9, mode=0o644, size=size)
    elif case == "transaction-record-mode":
        values["transaction_record_identity"] = _file_identity(11, mode=0o644)
    elif case == "stage-directory-mode":
        values["stage_dir_identity"] = _directory_identity(3, mode=0o750)
    elif case == "inputs-directory-mode":
        values["inputs_dir_identity"] = _directory_identity(5, mode=0o750)
    elif case == "backup-directory-mode":
        values["backup_dir_identity"] = _directory_identity(4, mode=0o750)
    elif case == "existing-container-writable":
        values["service_root_pre_identity"] = _directory_identity(20, mode=0o720)
        values["service_root_post_identity"] = _directory_identity(20, mode=0o720)
    else:
        values = _service_values(
            existing_service_directories=SERVICE_CONTAINER_ORDER[1:]
        )
        values["service_root_post_identity"] = _directory_identity(20, mode=0o750)
    with pytest.raises(ServiceTransactionError, match="mode|permissions|metadata|stage|pre-state"):
        _parse_values(values)


@pytest.mark.parametrize(
    ("field", "replacement", "message"),
    (
        ("signing_ca_key_stage_sha256", "f" * 64, "preserve"),
        (
            "signing_ca_certificate_stage_identity",
            _file_identity(501, mode=0o600),
            "object state",
        ),
        (
            "signing_ca_crlnumber_stage_identity",
            _file_identity(503, mode=0o600, size=2),
            "object state",
        ),
        (
            "signing_ca_config_stage_identity",
            _file_identity(502, mode=0o644),
            "object state",
        ),
        (
            "signing_ca_certificate_source_identity",
            _file_identity(401, mode=0o666),
            "unsafe mode",
        ),
        ("signing_inventory_stage_sha256", "f" * 64, "inventory private stage"),
        (
            "signing_root_certificate_stage_sha256",
            "f" * 64,
            "preserve",
        ),
        (
            "signing_inventory_source_identity",
            _file_identity(398, mode=0o666),
            "unsafe mode",
        ),
    ),
)
def test_signing_input_substitutions_and_unsafe_modes_are_rejected(
    field: str, replacement: str, message: str
) -> None:
    values = _service_values()
    values[field] = replacement
    with pytest.raises(ServiceTransactionError, match=message):
        _parse_values(values)


@pytest.mark.parametrize(
    "case", ("source-identity", "source-digest", "stage-digest", "stage-mode")
)
def test_reused_signing_key_must_bind_current_private_key(case: str) -> None:
    values = _service_values(key_action=ServiceKeyAction.REUSE)
    if case == "source-identity":
        values["signing_service_key_source_identity"] = _file_identity(999)
    elif case == "source-digest":
        values["signing_service_key_source_sha256"] = "f" * 64
    elif case == "stage-digest":
        values["signing_service_key_stage_sha256"] = "f" * 64
    else:
        values["signing_service_key_stage_identity"] = _file_identity(504, mode=0o644)
        values["signing_service_key_stage_object"] = _object_identity(504, mode=0o644)
    with pytest.raises(ServiceTransactionError, match="current key"):
        _parse_values(values)


def test_generated_or_rotated_key_rejects_redundant_signing_input_evidence() -> None:
    values = _service_values()
    values["signing_service_key_source"] = f"{PKI_DIR}/services/app/private/tls.key"
    with pytest.raises(ServiceTransactionError, match="disabled service signing input"):
        _parse_values(values)


def test_ca_old_state_and_newcert_have_exact_byte_continuity() -> None:
    journal = _parse_values(_service_values())
    mutations = {mutation.key: mutation for mutation in journal.mutations}
    for old_key, source_key in (
        ("ca_index_old", "ca_index"),
        ("ca_index_attr_old", "ca_index_attr"),
        ("ca_serial_old", "ca_serial"),
    ):
        old = mutations[old_key]
        source = mutations[source_key]
        assert old.stage_sha256 == source.pre_sha256
        assert isinstance(old.stage_identity, FileIdentity)
        assert isinstance(source.pre_identity, FileIdentity)
        assert old.stage_identity.permissions == source.pre_identity.permissions
        assert old.stage_identity.size == source.pre_identity.size
        assert old.stage_identity.mtime_ns == source.pre_identity.mtime_ns
    assert mutations["ca_newcert"].stage_sha256 == mutations[
        "service_certificate"
    ].stage_sha256


@pytest.mark.parametrize(
    ("key", "case"),
    (
        ("ca_index_old", "digest"),
        ("ca_index_attr_old", "digest"),
        ("ca_serial_old", "digest"),
        ("ca_index_old", "metadata"),
        ("ca_index_attr_old", "metadata"),
        ("ca_serial_old", "metadata"),
        ("ca_newcert", "digest"),
        ("ca_newcert", "size"),
    ),
)
def test_ca_byte_continuity_substitutions_are_independently_rejected(
    key: str, case: str
) -> None:
    values = _service_values()
    if case == "digest":
        values[f"{key}_stage_sha256"] = "f" * 64
    else:
        identity = values[f"{key}_stage_identity"].split(":", 6)
        inode = int(identity[1])
        mode = int(identity[3], 8)
        values[f"{key}_stage_identity"] = _file_identity(
            inode, mode=mode, size=2
        )
        values[f"{key}_stage_object"] = _object_identity(
            inode, mode=mode, size=2
        )
    with pytest.raises(
        ServiceTransactionError,
        match="authoritative pre-state|staged service certificate",
    ):
        _parse_values(values)


@pytest.mark.parametrize("case", ("digest", "size"))
def test_service_issuer_bytes_bind_claimed_generations(case: str) -> None:
    values = _service_values()
    if case == "digest":
        values["service_issuer_stage_sha256"] = "f" * 64
    else:
        values["service_issuer_stage_identity"] = _file_identity(105, size=1)
        values["service_issuer_stage_object"] = _object_identity(105, size=1)
    with pytest.raises(ServiceTransactionError, match="claimed issuer generations"):
        _parse_values(values)


@pytest.mark.parametrize(
    "existing",
    (
        (),
        ("service_root",),
        ("service_root", "service_private_dir", "service_csr_dir"),
        SERVICE_CONTAINER_ORDER,
    ),
)
def test_service_container_creation_order_and_existing_noops_are_exact(
    existing: tuple[str, ...],
) -> None:
    values = _service_values(existing_service_directories=existing)
    journal = _parse_values(values)
    created = tuple(key for key in SERVICE_CONTAINER_ORDER if key not in existing)
    assert journal.publication_order[: len(created)] == created
    mutations = {mutation.key: mutation for mutation in journal.mutations}
    for key in SERVICE_CONTAINER_ORDER:
        mutation = mutations[key]
        if key in existing:
            assert isinstance(mutation.post_identity, DirectoryIdentity)
            assert mutation.post_identity == mutation.pre_identity
            assert key not in journal.publication_order
        else:
            assert mutation.pre_identity is IdentitySentinel.ABSENT
            assert mutation.post_identity is IdentitySentinel.NONE

    if created:
        _set_post_prefix(values, len(created))
        values.update(
            phase="publishing",
            checkpoint="publication-done",
            mutation=created[-1],
        )
        published = _parse_values(values)
        published_mutations = {
            mutation.key: mutation for mutation in published.mutations
        }
        for key in created:
            identity = published_mutations[key].post_identity
            assert isinstance(identity, DirectoryIdentity)
            assert identity.permissions == 0o700


def test_created_service_containers_rollback_in_exact_reverse_before_cleanup() -> None:
    values = _service_values(existing_service_directories=())
    created = SERVICE_CONTAINER_ORDER
    assert _order(values)[: len(created)] == created
    for rolled_back in range(len(created)):
        pending = _service_values(existing_service_directories=())
        _set_post_prefix(pending, len(created))
        rollback = _set_rollback_prefix(pending, rolled_back)
        pending.update(
            phase="rolling-back",
            checkpoint="rollback-pending",
            mutation=rollback[rolled_back],
            outcome="failed-pre-commit",
        )
        _parse_values(pending)
        done = _service_values(existing_service_directories=())
        _set_post_prefix(done, len(created))
        rollback = _set_rollback_prefix(done, rolled_back + 1)
        done.update(
            phase="rolling-back",
            checkpoint="rollback-done",
            mutation=rollback[rolled_back],
            outcome="failed-pre-commit",
        )
        _parse_values(done)

    complete = _service_values(existing_service_directories=())
    _set_post_prefix(complete, len(created))
    rollback = _set_rollback_prefix(complete, len(created))
    complete.update(
        phase="rolling-back",
        checkpoint="rollback-done",
        mutation=rollback[-1],
        outcome="failed-pre-commit",
    )
    _parse_values(complete)
    _set_rollback_completion(complete)
    _clear_rollback_evidence(complete)
    complete.update(
        phase="cleaning-up",
        checkpoint="cleanup-stage-pending",
        mutation="none",
        recovery_mode="cleanup-only",
    )
    _parse_values(complete)


@pytest.mark.parametrize(
    "case",
    (
        "existing-replaced",
        "created-lacks-post",
        "child-without-parent",
        "created-rollback-not-absent",
        "existing-claims-rollback",
        "published-count-before-created-prefix",
    ),
)
def test_service_container_races_and_false_evidence_are_rejected(case: str) -> None:
    values = _service_values()
    if case == "existing-replaced":
        values["service_root_post_identity"] = _directory_identity(999)
    elif case == "created-lacks-post":
        values = _service_values(existing_service_directories=())
        _set_post_prefix(values, 1)
        values["service_root_post_identity"] = "none"
        values.update(
            phase="publishing",
            checkpoint="publication-done",
            mutation="service_root",
        )
    elif case == "child-without-parent":
        values = _service_values(
            existing_service_directories=SERVICE_CONTAINER_ORDER[1:]
        )
    elif case == "created-rollback-not-absent":
        values = _service_values(existing_service_directories=())
        _set_post_prefix(values, 1)
        rollback = _set_rollback_prefix(values, 1)
        values[f"{rollback[0]}_rollback_identity"] = _directory_identity(999)
        values.update(
            phase="rolling-back",
            checkpoint="rollback-done",
            mutation=rollback[0],
            outcome="failed-pre-commit",
        )
    elif case == "existing-claims-rollback":
        values["service_root_rollback_identity"] = "absent"
    else:
        values = _service_values(existing_service_directories=())
        values["published_count"] = "4"
    with pytest.raises(ServiceTransactionError):
        _parse_values(values)


@pytest.mark.parametrize(
    ("field", "replacement", "message"),
    (
        ("service_config_stage_identity", _file_identity(999), "stage identity"),
        ("service_config_stage_object", _object_identity(999), "stage identity"),
        ("ca_index_backup_identity", _file_identity(999), "backup identity"),
        ("ca_index_backup_object", _object_identity(999), "backup identity"),
        ("ca_index_backup_sha256", "f" * 64, "displaced pre-state"),
        ("ca_index_pre_sha256", "f" * 64, "displaced pre-state"),
        ("ca_index_pre_sha256", "none", "lacks a pre-state digest"),
    ),
)
def test_stage_backup_and_prestate_substitutions_are_independently_rejected(
    field: str, replacement: str, message: str
) -> None:
    values = _service_values()
    values[field] = replacement
    with pytest.raises(ServiceTransactionError, match=message):
        _parse_values(values)


def test_coherent_backup_identity_substitution_cannot_change_displaced_metadata() -> None:
    values = _service_values()
    values["ca_index_backup_identity"] = _file_identity(
        999,
        mtime="2026-08-11 12:00:03.000000000 +0000",
    )
    values["ca_index_backup_object"] = _object_identity(999)
    with pytest.raises(ServiceTransactionError, match="displaced pre-state"):
        _parse_values(values)


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("service_config_pre_sha256", DIGEST),
        ("service_config_backup", f"{PKI_DIR}/state/service/backup"),
        ("service_config_backup_identity", _file_identity(700)),
        ("service_config_backup_object", _object_identity(700)),
        ("service_config_backup_sha256", DIGEST),
    ),
)
def test_absent_destination_rejects_every_form_of_backup_evidence(
    field: str, replacement: str
) -> None:
    values = _service_values()
    values[field] = replacement
    with pytest.raises(ServiceTransactionError, match="backup evidence"):
        _parse_values(values)


@pytest.mark.parametrize("case", ("post-digest", "rollback-identity", "rollback-digest"))
def test_publication_and_rollback_substitutions_break_the_authenticity_chain(
    case: str,
) -> None:
    values = _service_values()
    order = _order(values)
    published = order.index("ca_index") + 1
    _set_post_prefix(values, published)
    if case == "post-digest":
        values["ca_index_post_sha256"] = "f" * 64
        values.update(
            phase="publishing",
            checkpoint="publication-done",
            mutation="ca_index",
        )
        message = "publication"
    else:
        rollback = _set_rollback_prefix(values, 1)
        values.update(
            phase="rolling-back",
            checkpoint="rollback-done",
            mutation=rollback[0],
            outcome="failed-pre-commit",
        )
        if case == "rollback-identity":
            values["ca_index_rollback_identity"] = _file_identity(999)
        else:
            values["ca_index_rollback_sha256"] = "f" * 64
        message = "backup"
    with pytest.raises(ServiceTransactionError, match=message):
        _parse_values(values)


@pytest.mark.parametrize(
    ("key_action", "has_key_publication", "has_archive"),
    (
        (ServiceKeyAction.REUSE, False, False),
        (ServiceKeyAction.CREATE, True, False),
        (ServiceKeyAction.ROTATE, True, True),
    ),
)
def test_issue_key_variants_have_exact_replacement_and_archive_binding(
    key_action: ServiceKeyAction,
    has_key_publication: bool,
    has_archive: bool,
) -> None:
    journal = _parse_values(_service_values(key_action=key_action))
    mutations = {mutation.key: mutation for mutation in journal.mutations}
    assert ("service_key" in mutations) is has_key_publication
    assert ("archive_key" in mutations) is has_archive
    if key_action is ServiceKeyAction.CREATE:
        assert mutations["service_key"].replace is False
        assert mutations["service_key"].pre_identity is IdentitySentinel.ABSENT
    elif key_action is ServiceKeyAction.ROTATE:
        key = mutations["service_key"]
        archived = mutations["archive_key"]
        assert key.replace is True
        assert archived.replace is False
        assert archived.archive_source == key.destination
        assert archived.archive_source_identity == key.pre_identity
        assert archived.archive_source_sha256 == archived.stage_sha256


@pytest.mark.parametrize(
    "member",
    MANAGED_RENEW_ARCHIVE_MEMBER_ORDER[1:-1],
)
def test_each_optional_renewal_archive_member_binds_its_displaced_source(
    member: str,
) -> None:
    values = _service_values(
        operation=ServiceOperation.RENEW,
        archive_members=(".platform-pki-renew-archive", member),
    )
    journal = _parse_values(values)
    mutations = {mutation.key: mutation for mutation in journal.mutations}
    archive_key = {
        "tls.crt": "archive_certificate",
        "tls.csr": "archive_csr",
        "ca-chain.crt": "archive_chain",
        "fullchain.crt": "archive_fullchain",
        "openssl.cnf": "archive_config",
        "issuer": "archive_issuer",
    }[member]
    source = mutations[ARCHIVE_SOURCE_KEYS[archive_key]]
    archived = mutations[archive_key]
    assert journal.archive_members == (".platform-pki-renew-archive", member)
    assert archived.archive_source == source.destination
    assert archived.archive_source_identity == source.pre_identity
    assert archived.archive_source_sha256 == source.pre_sha256
    assert archived.stage_sha256 == source.pre_sha256


@pytest.mark.parametrize("key_action", (ServiceKeyAction.REUSE, ServiceKeyAction.ROTATE))
def test_renewal_key_variants_bind_only_rotated_key_to_archive(
    key_action: ServiceKeyAction,
) -> None:
    values = _service_values(
        operation=ServiceOperation.RENEW,
        key_action=key_action,
        archive_members=(".platform-pki-renew-archive",),
    )
    journal = _parse_values(values)
    mutations = {mutation.key: mutation for mutation in journal.mutations}
    if key_action is ServiceKeyAction.REUSE:
        assert "service_key" not in mutations
        assert "archive_key" not in mutations
    else:
        assert journal.archive_members[-1] == "tls.key"
        assert mutations["service_key"].replace is True
        assert mutations["archive_key"].archive_source_identity == mutations[
            "service_key"
        ].pre_identity


@pytest.mark.parametrize(
    ("field", "replacement", "message"),
    (
        (
            "archive_certificate_source",
            f"{PKI_DIR}/services/app/csr/tls.csr",
            "path",
        ),
        ("archive_certificate_source_identity", _file_identity(999), "pre-state"),
        ("archive_certificate_source_sha256", "f" * 64, "staged content"),
        ("archive_certificate_stage_sha256", "e" * 64, "staged content"),
        (
            "archive_certificate_stage_identity",
            _file_identity(
                999,
                mtime="2026-08-11 12:00:03.000000000 +0000",
            ),
            "stage identity",
        ),
    ),
)
def test_archive_substitution_evidence_is_rejected(
    field: str, replacement: str, message: str
) -> None:
    values = _service_values(
        operation=ServiceOperation.RENEW,
        archive_members=(".platform-pki-renew-archive", "tls.crt"),
    )
    values[field] = replacement
    with pytest.raises(ServiceTransactionError, match=message):
        _parse_values(values)


def test_optional_renewal_members_cannot_disagree_with_source_presence() -> None:
    omitted = _service_values(
        operation=ServiceOperation.RENEW,
        archive_members=(".platform-pki-renew-archive",),
    )
    omitted["service_certificate_pre_identity"] = _file_identity(700)
    omitted["service_certificate_pre_sha256"] = _evidence_digest(
        "pre:service_certificate"
    )
    omitted["service_certificate_backup"] = (
        f"{omitted['backup_dir']}/service_certificate"
    )
    omitted["service_certificate_backup_identity"] = _file_identity(701)
    omitted["service_certificate_backup_object"] = _object_identity(701)
    omitted["service_certificate_backup_sha256"] = omitted[
        "service_certificate_pre_sha256"
    ]
    omitted["backed_up_count"] = str(len(_backup_order(omitted)))
    with pytest.raises(ServiceTransactionError, match="members"):
        _parse_values(omitted)

    claimed = _service_values(
        operation=ServiceOperation.RENEW,
        archive_members=(".platform-pki-renew-archive", "tls.crt"),
    )
    claimed["service_certificate_pre_identity"] = "absent"
    claimed["service_certificate_pre_sha256"] = "none"
    claimed["service_certificate_backup"] = "none"
    claimed["service_certificate_backup_identity"] = "none"
    claimed["service_certificate_backup_object"] = "none"
    claimed["service_certificate_backup_sha256"] = "none"
    claimed["backed_up_count"] = str(len(_backup_order(claimed)))
    with pytest.raises(ServiceTransactionError, match="pre-state"):
        _parse_values(claimed)


@pytest.mark.parametrize("mutation", ("duplicate", "unknown", "missing", "reordered", "empty", "control", "no-newline", "extra-newline"))
def test_service_journal_rejects_noncanonical_records(mutation: str) -> None:
    values = _service_values()
    lines = _payload(SERVICE_TRANSACTION_FIELDS, values).splitlines()
    if mutation == "duplicate":
        lines[-1] = lines[0]
    elif mutation == "unknown":
        lines[-1] = b"unknown=value"
    elif mutation == "missing":
        lines.pop()
    elif mutation == "reordered":
        lines[0], lines[1] = lines[1], lines[0]
    elif mutation == "empty":
        lines[-1] = lines[-1].partition(b"=")[0] + b"="
    elif mutation == "control":
        lines[-1] += b"\t"
    data = b"\n".join(lines)
    if mutation != "no-newline":
        data += b"\n"
    if mutation == "extra-newline":
        data += b"\n"
    with pytest.raises(ServiceTransactionError):
        parse_service_transaction(data, pki_dir=PKI_DIR)


@pytest.mark.parametrize(
    ("operation", "key_action", "archive_members"),
    (
        (ServiceOperation.ISSUE, ServiceKeyAction.REUSE, None),
        (ServiceOperation.ISSUE, ServiceKeyAction.CREATE, None),
        (ServiceOperation.ISSUE, ServiceKeyAction.ROTATE, None),
        (
            ServiceOperation.RENEW,
            ServiceKeyAction.REUSE,
            (".platform-pki-renew-archive",),
        ),
        (
            ServiceOperation.RENEW,
            ServiceKeyAction.REUSE,
            MANAGED_RENEW_ARCHIVE_MEMBER_ORDER[:-1],
        ),
        (
            ServiceOperation.RENEW,
            ServiceKeyAction.ROTATE,
            MANAGED_RENEW_ARCHIVE_MEMBER_ORDER[:-1],
        ),
    ),
)
def test_every_stage_and_backup_restart_checkpoint_accepts_exact_prefixes(
    operation: ServiceOperation,
    key_action: ServiceKeyAction,
    archive_members: tuple[str, ...] | None,
) -> None:
    arguments = {
        "operation": operation,
        "key_action": key_action,
        "archive_members": archive_members,
    }
    staging_order = _staging_order(_service_values(**arguments))
    for index, key in enumerate(staging_order):
        pending = _service_values(**arguments)
        assert _set_stage_prefix(pending, index) == staging_order
        pending.update(
            phase="staging",
            checkpoint="staging-pending",
            mutation=key,
        )
        assert _parse_values(pending).staging_order == staging_order

        done = _service_values(**arguments)
        _set_stage_prefix(done, index + 1)
        done.update(
            phase="staging",
            checkpoint="staging-done",
            mutation=key,
        )
        _parse_values(done)

    backup_order = _backup_order(_service_values(**arguments))
    for index, key in enumerate(backup_order):
        pending = _service_values(**arguments)
        assert _set_backup_prefix(pending, index) == backup_order
        pending.update(
            phase="backing-up",
            checkpoint="backup-pending",
            mutation=key,
        )
        assert _parse_values(pending).backup_order == backup_order

        done = _service_values(**arguments)
        _set_backup_prefix(done, index + 1)
        done.update(
            phase="backing-up",
            checkpoint="backup-done",
            mutation=key,
        )
        _parse_values(done)


def test_every_legal_issue_publication_and_verification_checkpoint_round_trips() -> None:
    planned = _service_values()
    assert _parse_values(planned).phase is ServicePhase.PLANNED
    order = _order(planned)
    for index, key in enumerate(order):
        pending = _service_values()
        _set_post_prefix(pending, index)
        pending.update(phase="publishing", checkpoint="publication-pending", mutation=key)
        assert _parse_values(pending).publication_order == order
        done = _service_values()
        _set_post_prefix(done, index + 1)
        done.update(phase="publishing", checkpoint="publication-done", mutation=key)
        _parse_values(done)
    for checkpoint in ("verification-pending", "verification-done"):
        values = _service_values()
        _set_post_prefix(values, len(order))
        values.update(phase="verifying", checkpoint=checkpoint)
        _parse_values(values)


def test_pending_created_directory_may_bind_exact_private_stage_identity() -> None:
    values = _service_values(existing_service_directories=())
    key = _order(values)[0]
    assert key == "service_root"
    values[f"{key}_post_identity"] = _directory_identity(90)
    values.update(
        phase="publishing",
        checkpoint="publication-pending",
        mutation=key,
    )

    journal = _parse_values(values)

    assert isinstance(journal.mutations[0].post_identity, DirectoryIdentity)

    values["checkpoint"] = "planned"
    values["phase"] = "planned"
    values["mutation"] = "none"
    with pytest.raises(ServiceTransactionError, match="post identities"):
        _parse_values(values)


def test_every_reverse_rollback_checkpoint_accepts_only_exact_restoration() -> None:
    order = _order(_service_values())
    for published in range(1, len(order) + 1):
        for rolled_back in range(published):
            rollback = tuple(reversed(order[:published]))
            pending = _service_values()
            _set_post_prefix(pending, published)
            _set_rollback_prefix(pending, rolled_back)
            pending.update(
                phase="rolling-back",
                checkpoint="rollback-pending",
                mutation=rollback[rolled_back],
                outcome="failed-pre-commit",
            )
            assert _parse_values(pending).rollback_order == tuple(reversed(order))
            done = _service_values()
            _set_post_prefix(done, published)
            _set_rollback_prefix(done, rolled_back + 1)
            done.update(
                phase="rolling-back",
                checkpoint="rollback-done",
                mutation=rollback[rolled_back],
                outcome="failed-pre-commit",
            )
            _parse_values(done)


def test_every_rollback_completion_restart_checkpoint_accepts_exact_prefix() -> None:
    order = _order(_service_values())
    for published in range(len(order) + 1):
        pending = _service_values()
        _set_post_prefix(pending, published)
        _set_rollback_prefix(pending, published)
        _set_rollback_completion(pending, pending=True)
        pending.update(
            phase="rolling-back",
            checkpoint="rollback-completion-pending",
            mutation="none",
            outcome="failed-pre-commit",
        )
        _parse_values(pending)

        completed = _service_values()
        _set_post_prefix(completed, published)
        _set_rollback_prefix(completed, published)
        completion_bytes = _set_rollback_completion(completed)
        assert completion_bytes is not None
        completed.update(
            phase="rolling-back",
            checkpoint="rollback-completion-done",
            mutation="none",
            outcome="failed-pre-commit",
        )
        _parse_values(completed)

        completed["checkpoint"] = "rollback-evidence-clear-pending"
        _parse_values(completed)

        _clear_rollback_evidence(completed)
        completed.update(
            phase="cleaning-up",
            checkpoint="cleanup-stage-pending",
            recovery_mode="cleanup-only",
        )
        _parse_values(completed)


@pytest.mark.parametrize(
    "case",
    (
        "staged-overflow",
        "staged-undercount",
        "staged-overclaim",
        "backup-overflow",
        "backup-undercount",
        "backup-overclaim",
        "backup-before-staging",
        "publication-before-backup",
        "publication-overflow",
        "publication-undercount",
        "publication-overclaim",
        "rollback-over-published",
        "rollback-undercount",
        "rollback-overclaim",
        "completion-over-published",
    ),
)
def test_every_progress_counter_rejects_skips_overcounts_and_false_prefixes(
    case: str,
) -> None:
    values = _service_values()
    staging_order = _staging_order(values)
    backup_order = _backup_order(values)
    publication_order = _order(values)
    if case == "staged-overflow":
        values["staged_count"] = str(len(staging_order) + 1)
    elif case == "staged-undercount":
        values["staged_count"] = str(len(staging_order) - 1)
    elif case == "staged-overclaim":
        key = staging_order[-1]
        values[f"{key}_stage_identity"] = "none"
        values[f"{key}_stage_object"] = "none"
        values[f"{key}_stage_sha256"] = "none"
    elif case == "backup-overflow":
        values["backed_up_count"] = str(len(backup_order) + 1)
    elif case == "backup-undercount":
        values["backed_up_count"] = str(len(backup_order) - 1)
    elif case == "backup-overclaim":
        key = backup_order[-1]
        values[f"{key}_backup_identity"] = "none"
        values[f"{key}_backup_object"] = "none"
        values[f"{key}_backup_sha256"] = "none"
    elif case == "backup-before-staging":
        key = staging_order[-1]
        values["staged_count"] = str(len(staging_order) - 1)
        values[f"{key}_stage_identity"] = "none"
        values[f"{key}_stage_object"] = "none"
        values[f"{key}_stage_sha256"] = "none"
    elif case == "publication-before-backup":
        _set_backup_prefix(values, len(backup_order) - 1)
        _set_post_prefix(values, 1)
    elif case == "publication-overflow":
        values["published_count"] = str(len(publication_order) + 1)
    elif case == "publication-undercount":
        _set_post_prefix(values, 2)
        values["published_count"] = "1"
    elif case == "publication-overclaim":
        _set_post_prefix(values, 1)
        values["published_count"] = "2"
    elif case == "rollback-over-published":
        _set_post_prefix(values, 1)
        values["rollback_count"] = "2"
    elif case == "rollback-undercount":
        _set_post_prefix(values, 2)
        _set_rollback_prefix(values, 2)
        values["rollback_count"] = "1"
    elif case == "rollback-overclaim":
        _set_post_prefix(values, 2)
        _set_rollback_prefix(values, 1)
        values["rollback_count"] = "2"
    else:
        values["rollback_completion_count"] = "1"
    with pytest.raises(ServiceTransactionError):
        _parse_values(values)


def test_failed_cleanup_requires_durable_full_rollback_completion() -> None:
    values = _service_values()
    _set_post_prefix(values, 5)
    _set_rollback_prefix(values, 5)
    _clear_rollback_evidence(values)
    values.update(
        phase="cleaning-up",
        checkpoint="cleanup-stage-pending",
        mutation="none",
        recovery_mode="cleanup-only",
        outcome="failed-pre-commit",
    )
    with pytest.raises(ServiceTransactionError, match="phase and evidence"):
        _parse_values(values)


def _committed_values(*, renew: bool = False) -> dict[str, str]:
    values = _service_values(operation=(ServiceOperation.RENEW if renew else ServiceOperation.ISSUE))
    order = _order(values)
    _set_post_prefix(values, len(order))
    values.update(
        phase="committed",
        checkpoint="commit-done",
        committed="true",
        recovery_mode="cleanup-only",
        outcome="succeeded",
    )
    return values


def _set_cleanup(values: dict[str, str], checkpoint: str, *, renew: bool) -> None:
    steps = ["stage", "backup", "terminal"]
    if renew:
        steps.insert(0, "archive-marker")
    if checkpoint == "journal-cleanup-pending":
        completed = len(steps)
    else:
        name, state = checkpoint.removeprefix("cleanup-").rsplit("-", 1)
        completed = steps.index(name) + (state == "done")
    values["archive_marker_removed"] = (
        str(steps.index("archive-marker") < completed).lower() if renew else "none"
    )
    values["stage_removed"] = str(steps.index("stage") < completed).lower()
    values["backup_removed"] = str(steps.index("backup") < completed).lower()
    if steps.index("terminal") < completed:
        _set_terminal(values)


@pytest.mark.parametrize("renew", (False, True), ids=("issue", "renew"))
def test_committed_and_cleanup_only_phase_matrix(renew: bool) -> None:
    committed = _committed_values(renew=renew)
    assert _parse_values(committed).recovery_mode is ServiceRecoveryMode.CLEANUP_ONLY
    steps = ["stage", "backup", "terminal"]
    if renew:
        steps.insert(0, "archive-marker")
    checkpoints = [
        checkpoint
        for step in steps
        for checkpoint in (f"cleanup-{step}-pending", f"cleanup-{step}-done")
    ]
    for checkpoint in checkpoints:
        values = _committed_values(renew=renew)
        values.update(phase="cleaning-up", checkpoint=checkpoint)
        _set_cleanup(values, checkpoint, renew=renew)
        _parse_values(values)
    terminal = _committed_values(renew=renew)
    terminal.update(phase="terminal", checkpoint="journal-cleanup-pending")
    _set_cleanup(terminal, "journal-cleanup-pending", renew=renew)
    assert _parse_values(terminal).phase is ServicePhase.TERMINAL


@pytest.mark.parametrize("phase", ("cleaning-up", "terminal"))
@pytest.mark.parametrize("progress", ("staging", "backup", "publication"))
def test_successful_cleanup_retains_complete_committed_prefixes(
    phase: str, progress: str
) -> None:
    values = _committed_values()
    if progress == "staging":
        _set_stage_prefix(values, len(_staging_order(values)) - 1)
        _set_post_prefix(values, 0)
    elif progress == "backup":
        _set_backup_prefix(values, len(_backup_order(values)) - 1)
        _set_post_prefix(values, 0)
    else:
        _set_post_prefix(values, len(_order(values)) - 1)
    if phase == "terminal":
        values.update(phase="terminal", checkpoint="journal-cleanup-pending")
        _set_cleanup(values, "journal-cleanup-pending", renew=False)
    else:
        values.update(phase="cleaning-up", checkpoint="cleanup-stage-pending")
    with pytest.raises(ServiceTransactionError, match="committed prefixes"):
        _parse_values(values)


def _failed_cleanup_values(*, terminal: bool) -> dict[str, str]:
    values = _service_values()
    _set_post_prefix(values, 5)
    _set_rollback_prefix(values, 5)
    _set_rollback_completion(values)
    _clear_rollback_evidence(values)
    values.update(
        phase="terminal" if terminal else "cleaning-up",
        checkpoint=("journal-cleanup-pending" if terminal else "cleanup-stage-pending"),
        mutation="none",
        recovery_mode="cleanup-only",
        outcome="failed-pre-commit",
    )
    if terminal:
        _set_cleanup(values, "journal-cleanup-pending", renew=False)
    return values


@pytest.mark.parametrize(
    ("phase_case", "evidence_case"),
    tuple(
        (phase_case, evidence_case)
        for phase_case in (
            "committed",
            "cleaning-success",
            "terminal-success",
            "cleaning-failed",
            "terminal-failed",
        )
        for evidence_case in ("count", "identity", "digest")
    ),
)
def test_every_post_boundary_phase_rejects_all_rollback_evidence(
    phase_case: str, evidence_case: str
) -> None:
    if phase_case in {"committed", "cleaning-success", "terminal-success"}:
        values = _committed_values()
        if phase_case == "cleaning-success":
            values.update(phase="cleaning-up", checkpoint="cleanup-stage-pending")
        elif phase_case == "terminal-success":
            values.update(phase="terminal", checkpoint="journal-cleanup-pending")
            _set_cleanup(values, "journal-cleanup-pending", renew=False)
    else:
        values = _failed_cleanup_values(terminal=phase_case == "terminal-failed")
    if evidence_case == "count":
        values["rollback_count"] = "1"
    elif evidence_case == "identity":
        values["service_config_rollback_identity"] = "absent"
    else:
        values["service_config_rollback_sha256"] = DIGEST
    with pytest.raises(ServiceTransactionError, match="post-boundary"):
        _parse_values(values)
    assert not any(field.endswith("_rollback_object") for field in SERVICE_TRANSACTION_FIELDS)


@pytest.mark.parametrize(
    "field",
    (
        "transaction",
        "operation",
        "service",
        "outcome",
        "committed",
        "transaction_identity",
        "transaction_sha256",
        "rollback_completion_identity",
        "rollback_completion_sha256",
    ),
)
def test_terminal_digest_rejects_canonical_field_substitution(field: str) -> None:
    values = _committed_values()
    values.update(phase="terminal", checkpoint="journal-cleanup-pending")
    _set_cleanup(values, "journal-cleanup-pending", renew=False)
    terminal = {
        "schema": "1",
        "transaction": values["transaction"],
        "operation": values["operation"],
        "service": values["service"],
        "outcome": values["outcome"],
        "committed": values["committed"],
        "transaction_identity": values["transaction_record_identity"],
        "transaction_sha256": values["transaction_record_sha256"],
        "rollback_completion_identity": values["rollback_completion_identity"],
        "rollback_completion_sha256": values["rollback_completion_sha256"],
    }
    terminal[field] = {
        "transaction": "service-ffffffffffffffffffffffffffffffff",
        "operation": "service-renew",
        "service": "other",
        "outcome": "failed-pre-commit",
        "committed": "false",
        "transaction_identity": _file_identity(999, size=1),
        "transaction_sha256": "f" * 64,
        "rollback_completion_identity": _file_identity(998, size=1),
        "rollback_completion_sha256": "e" * 64,
    }[field]
    values["terminal_sha256"] = sha256(
        _payload(SERVICE_RETAINED_TERMINAL_FIELDS, terminal)
    ).hexdigest()
    with pytest.raises(ServiceTransactionError, match="canonical bytes"):
        _parse_values(values)


def test_terminal_requires_private_mode_and_legal_cleanup_phase() -> None:
    values = _committed_values()
    values.update(phase="terminal", checkpoint="journal-cleanup-pending")
    _set_cleanup(values, "journal-cleanup-pending", renew=False)
    values["terminal_identity"] = _file_identity(900, mode=0o644)
    with pytest.raises(ServiceTransactionError, match="wrong mode"):
        _parse_values(values)

    values = _committed_values()
    _set_terminal(values)
    with pytest.raises(ServiceTransactionError, match="premature cleanup"):
        _parse_values(values)


def test_uncommitted_rollback_becomes_cleanup_only_only_after_reverse_completion() -> None:
    values = _service_values()
    order = _order(values)
    _set_post_prefix(values, 5)
    _set_rollback_prefix(values, 5)
    values.update(
        phase="rolling-back",
        checkpoint="rollback-done",
        mutation=tuple(reversed(order[:5]))[4],
        outcome="failed-pre-commit",
    )
    _parse_values(values)
    _set_rollback_completion(values)
    _clear_rollback_evidence(values)
    values.update(
        phase="cleaning-up",
        checkpoint="cleanup-stage-pending",
        mutation="none",
        recovery_mode="cleanup-only",
    )
    _parse_values(values)
    values["rollback_count"] = "1"
    with pytest.raises(ServiceTransactionError, match="rollback"):
        _parse_values(values)
    assert managed_rollback_order(order[:5]) == tuple(reversed(order[:5]))


@pytest.mark.parametrize("existing_archive_root", (False, True))
def test_renewal_rollback_order_matches_retained_container_sequence(
    existing_archive_root: bool,
) -> None:
    values = _service_values(
        operation=ServiceOperation.RENEW,
        existing_archive_root=existing_archive_root,
        existing_service_directories=(),
    )
    publication = _order(values)
    ordinary = tuple(
        key
        for key in publication
        if key not in {*SERVICE_CONTAINER_ORDER, "archive_root", "archive_dir"}
    )
    expected = (*reversed(ordinary), "archive_dir")
    if not existing_archive_root:
        expected = (*expected, "archive_root")
    expected = (*expected, *reversed(SERVICE_CONTAINER_ORDER))
    assert managed_rollback_order(publication) == expected

    _set_post_prefix(values, len(publication))
    _set_rollback_prefix(values, len(publication))
    values.update(
        phase="rolling-back",
        checkpoint="rollback-completion-done",
        mutation="none",
        outcome="failed-pre-commit",
    )
    if existing_archive_root:
        values.update(
            archive_root_restored="true",
            archive_root_restored_identity=_full_directory_identity(
                12,
                ctime="2026-08-11 12:00:02.000000000 +0000",
            ),
        )
    _set_rollback_completion(values)
    _parse_values(values)


def test_archive_root_restoration_is_rejected_before_ordinary_rollback() -> None:
    values = _service_values(
        operation=ServiceOperation.RENEW,
        existing_archive_root=True,
    )
    publication = _order(values)
    _set_post_prefix(values, len(publication))
    rollback = _set_rollback_prefix(values, 1)
    values.update(
        phase="rolling-back",
        checkpoint="rollback-done",
        mutation=rollback[0],
        outcome="failed-pre-commit",
        archive_root_restored="true",
        archive_root_restored_identity=_full_directory_identity(
            12,
            ctime="2026-08-11 12:00:02.000000000 +0000",
        ),
    )
    with pytest.raises(ServiceTransactionError, match="restoration ordering"):
        _parse_values(values)


def test_existing_archive_root_restoration_precedes_created_directory_rollback() -> None:
    values = _service_values(
        operation=ServiceOperation.RENEW,
        existing_archive_root=True,
        existing_service_directories=(),
    )
    publication = _order(values)
    _set_post_prefix(values, len(publication))
    rollback = managed_rollback_order(publication)
    boundary = rollback.index("archive_dir") + 1
    _set_rollback_prefix(values, boundary)
    values.update(
        phase="rolling-back",
        checkpoint="archive-root-restore-pending",
        mutation="none",
        outcome="failed-pre-commit",
    )
    _parse_values(values)
    values.update(
        checkpoint="archive-root-restore-done",
        archive_root_restored="true",
        archive_root_restored_identity=_full_directory_identity(
            12,
            ctime="2026-08-11 12:00:02.000000000 +0000",
        ),
    )
    _parse_values(values)

    _set_rollback_prefix(values, boundary + 1)
    values.update(
        checkpoint="rollback-done",
        mutation=rollback[boundary],
    )
    _parse_values(values)


def test_rollback_completion_is_rejected_before_required_archive_root_restoration() -> None:
    values = _service_values(
        operation=ServiceOperation.RENEW,
        existing_archive_root=True,
    )
    publication = _order(values)
    _set_post_prefix(values, len(publication))
    _set_rollback_prefix(values, len(publication))
    _set_rollback_completion(values)
    values.update(
        phase="rolling-back",
        checkpoint="rollback-completion-done",
        mutation="none",
        outcome="failed-pre-commit",
        archive_root_restored="true",
        archive_root_restored_identity=_full_directory_identity(
            12,
            ctime="2026-08-11 12:00:02.000000000 +0000",
        ),
    )
    with pytest.raises(ServiceTransactionError, match="full reverse prefix"):
        _parse_values(values)


def test_existing_archive_root_requires_ordered_metadata_restoration_before_cleanup() -> None:
    values = _service_values(
        operation=ServiceOperation.RENEW,
        existing_archive_root=True,
    )
    order = _order(values)
    _set_post_prefix(values, len(order))
    _set_rollback_prefix(values, len(order))
    values.update(
        phase="rolling-back",
        checkpoint="archive-root-restore-pending",
        mutation="none",
        outcome="failed-pre-commit",
    )
    _parse_values(values)
    values.update(
        checkpoint="archive-root-restore-done",
        archive_root_restored="true",
        archive_root_restored_identity=_full_directory_identity(
            12,
            ctime="2026-08-11 12:00:02.000000000 +0000",
        ),
    )
    _parse_values(values)
    _set_rollback_completion(values)
    values.update(
        phase="cleaning-up",
        checkpoint="cleanup-stage-pending",
        recovery_mode="cleanup-only",
    )
    _clear_rollback_evidence(values)
    _parse_values(values)
    values["archive_root_restored"] = "false"
    values["archive_root_restored_identity"] = "none"
    with pytest.raises(ServiceTransactionError, match="full reverse prefix"):
        _parse_values(values)


@pytest.mark.parametrize(
    ("field", "replacement", "message"),
    (
        ("archive_root_reference_sha256", DIGEST, "reference digest"),
        (
            "archive_root_reference_identity",
            _file_identity(
                13,
                size=0,
                mtime="2026-08-11 12:00:03.000000000 +0000",
            ),
            "original metadata",
        ),
    ),
)
def test_existing_archive_root_reference_is_exact(
    field: str, replacement: str, message: str
) -> None:
    values = _service_values(
        operation=ServiceOperation.RENEW,
        existing_archive_root=True,
    )
    values[field] = replacement
    with pytest.raises(ServiceTransactionError, match=message):
        _parse_values(values)


def test_archive_root_restoration_requires_mutated_container_and_exact_identity() -> None:
    values = _service_values(
        operation=ServiceOperation.RENEW,
        existing_archive_root=True,
    )
    _set_post_prefix(values, 1)
    _set_rollback_prefix(values, 1)
    values.update(
        archive_root_restored="true",
        archive_root_restored_identity=_full_directory_identity(12),
    )
    _set_rollback_completion(values)
    _clear_rollback_evidence(values)
    values.update(
        phase="cleaning-up",
        checkpoint="cleanup-stage-pending",
        recovery_mode="cleanup-only",
        outcome="failed-pre-commit",
    )
    with pytest.raises(ServiceTransactionError, match="not required"):
        _parse_values(values)

    values = _service_values(
        operation=ServiceOperation.RENEW,
        existing_archive_root=True,
    )
    order = _order(values)
    _set_post_prefix(values, len(order))
    _set_rollback_prefix(values, len(order))
    values.update(
        phase="rolling-back",
        checkpoint="archive-root-restore-done",
        outcome="failed-pre-commit",
        archive_root_restored="true",
        archive_root_restored_identity=_full_directory_identity(999),
    )
    with pytest.raises(ServiceTransactionError, match="original metadata"):
        _parse_values(values)


def test_archive_container_rollback_must_be_the_exact_reverse_prefix() -> None:
    values = _service_values(
        operation=ServiceOperation.RENEW,
        key_action=ServiceKeyAction.ROTATE,
        archive_members=(".platform-pki-renew-archive", "issuer"),
    )
    order = _order(values)
    _set_post_prefix(values, len(order))
    rollback = _set_rollback_prefix(values, 3)
    assert rollback[:3] == ("archive_key", "archive_issuer", "archive_marker")
    values.update(
        phase="rolling-back",
        checkpoint="rollback-done",
        mutation=rollback[2],
        outcome="failed-pre-commit",
    )
    values["archive_dir_rollback_identity"] = "absent"
    with pytest.raises(ServiceTransactionError, match="reverse prefix"):
        _parse_values(values)


@pytest.mark.parametrize(
    "field,replacement",
    (
        ("journal_path", f"{PKI_DIR}/state/service/../service/recovery-journal"),
        ("transaction_dir", f"{PKI_DIR}/state/service/transactions/service-{REQUEST_ID}x"),
        ("inputs_dir", f"{PKI_DIR}/state/service/transactions/service-{REQUEST_ID}/inputs"),
        ("service_certificate_destination", f"{PKI_DIR}/services/app/certs/../certs/tls.crt"),
        ("ca_index_destination", f"{PKI_DIR}/authorities/intermediates/g1-i10/index.txt"),
        ("service_config_stage", f"{PKI_DIR}/state/service/transactions/service-{REQUEST_ID}/stagex/service_config"),
        ("ca_index_backup", "/tmp/ca_index"),
        ("signing_inventory_source", f"{PKI_DIR}/inventory/other.yml"),
    ),
)
def test_service_paths_reject_escape_prefix_and_binding_mismatches(field: str, replacement: str) -> None:
    values = _service_values()
    values[field] = replacement
    with pytest.raises(ServiceTransactionError, match="path"):
        _parse_values(values)


def test_operation_key_archive_and_identity_constraints_are_exact() -> None:
    renew = _service_values(operation=ServiceOperation.RENEW, key_action=ServiceKeyAction.ROTATE)
    journal = _parse_values(renew)
    assert journal.archive_state is ServiceArchiveState.RENEW
    assert journal.publication_order[-5:] == (
        "archive_root",
        "archive_dir",
        "archive_marker",
        "archive_issuer",
        "archive_key",
    )
    assert journal.rollback_order == managed_rollback_order(
        journal.publication_order
    )

    invalid = _service_values(operation=ServiceOperation.RENEW)
    invalid["key_action"] = "create"
    invalid["current_key_identity"] = "absent"
    with pytest.raises(ServiceTransactionError, match="renewal cannot create"):
        _parse_values(invalid)

    invalid = _service_values()
    invalid["service_certificate_pre_identity"] = _file_identity(800)
    invalid["service_certificate_backup_identity"] = _file_identity(801)
    with pytest.raises(ServiceTransactionError, match="no-clobber"):
        _parse_values(invalid)

    invalid = _service_values()
    invalid["ca_index_pre_identity"] = "absent"
    invalid["ca_index_pre_sha256"] = "none"
    invalid["ca_index_backup"] = "none"
    invalid["ca_index_backup_identity"] = "none"
    invalid["ca_index_backup_object"] = "none"
    invalid["ca_index_backup_sha256"] = "none"
    with pytest.raises(ServiceTransactionError, match="required CA state"):
        _parse_values(invalid)

    invalid = _service_values()
    invalid["transaction_identity"] = "1:2:1000:755:directory"
    with pytest.raises(ServiceTransactionError, match="wrong mode"):
        _parse_values(invalid)

    invalid = _service_values()
    invalid["service_config_stage_identity"] = _file_identity(100).replace(":1:1:", ":2:1:")
    with pytest.raises(ServiceTransactionError, match="single-link"):
        _parse_values(invalid)


def test_illegal_evidence_windows_and_forward_only_commit_boundary_are_rejected() -> None:
    values = _service_values()
    values["service_config_post_sha256"] = values["service_config_stage_sha256"]
    with pytest.raises(ServiceTransactionError, match="without publication identity"):
        _parse_values(values)

    values = _service_values()
    values["service_config_rollback_sha256"] = DIGEST
    with pytest.raises(ServiceTransactionError, match="without rollback identity"):
        _parse_values(values)

    values = _service_values()
    values["service_config_post_identity"] = values["service_config_stage_identity"]
    with pytest.raises(ServiceTransactionError, match="publication"):
        _parse_values(values)

    values = _service_values()
    published = _order(values).index("ca_index") + 1
    _set_post_prefix(values, published)
    _set_rollback_prefix(values, 1)
    values["ca_index_rollback_sha256"] = "none"
    values.update(
        phase="rolling-back",
        checkpoint="rollback-done",
        mutation="ca_index",
        outcome="failed-pre-commit",
    )
    with pytest.raises(ServiceTransactionError, match="lacks a digest"):
        _parse_values(values)

    values = _committed_values()
    values.update(committed="false", recovery_mode="rollback")
    with pytest.raises(ServiceTransactionError, match="phase and evidence"):
        _parse_values(values)

    values = _committed_values()
    values.update(phase="rolling-back", checkpoint="rollback-pending", mutation="service_key", outcome="failed-pre-commit")
    with pytest.raises(ServiceTransactionError, match="phase and evidence"):
        _parse_values(values)

    values = _service_values()
    values["stage_removed"] = "true"
    with pytest.raises(ServiceTransactionError, match="premature cleanup"):
        _parse_values(values)

    values = _service_values()
    _set_post_prefix(values, 1)
    values["service_config_post_identity"] = _file_identity(999)
    values.update(phase="publishing", checkpoint="publication-done", mutation="service_config")
    with pytest.raises(ServiceTransactionError, match="publication"):
        _parse_values(values)

    values = _service_values(key_action=ServiceKeyAction.ROTATE)
    values["archive_key_post_identity"] = values["archive_key_stage_identity"]
    with pytest.raises(ServiceTransactionError, match="publication"):
        _parse_values(values)
