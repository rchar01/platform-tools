from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import FrozenInstanceError
from itertools import product
from pathlib import Path

import pytest

from src.platform_pki.csr_recovery import (
    CANDIDATE_FINALIZATION_FIXED_FIELDS,
    CANDIDATE_FINALIZATION_JOURNAL_FIELDS,
    CANDIDATE_SOURCE_KEYS,
    CANDIDATE_SOURCE_PATHS,
    CSR_DB_KEYS,
    CSR_DB_PATHS,
    CSR_DB_SUFFIXES,
    CSR_SIGNING_FIXED_FIELDS,
    CSR_SIGNING_JOURNAL_FIELDS,
    SIGNING_PLANNED_STEPS,
    ActivePublicationMode,
    CsrRecoveryError,
    FinalizationPhase,
    SigningPhase,
    SigningRecoveryStep,
    parse_finalization_journal,
    parse_finalization_journal_structure,
    parse_signing_journal,
    parse_signing_journal_structure,
    validate_signing_transaction_presence,
)
from src.platform_pki.filesystem import DirectoryIdentity, FileIdentity, FileObjectState
from src.platform_pki.persisted_identity import IdentitySentinel


PKI_DIR = "/srv/platform/pki"
ROOT = Path(__file__).resolve().parents[1]
ORACLE_ROOT = ROOT / "tests/pki/oracles/platform-pki-csr-recover"
ORACLE_COMMIT = "0843c1c11b952aab39f5c95b5eced82989656eb3"
ORACLE_HASHES = {
    "platform-pki-csr-recover": "181528862958bf5a0810b3cae5c773b5f3d395c68226f2e2d17f019ad0757271",
    "lib/platform-pki-common.sh": "dee644be8ab6236cb368a553493f55b53a90c3aead291550f7e635c080a5494f",
    "lib/platform-pki-csr-sign.sh": "8659a730f91c592c12fa3d40acbb080cf10d3eff6bd2de38fa486e8055f3e001",
    "lib/platform-pki-csr-candidate.sh": "ca1fb976f09730fbbc840ce97cb0c6db3ae76e5d679fdc777a1a96d80df5b43f",
}
DIGEST = "0" * 64
DIRECTORY_IDENTITY = "1:2:1000:700:directory"
FILE_IDENTITY = (
    "1:3:1000:600:1:1:2026-08-10 12:00:00.000000000 +0000:"
    "2026-08-10 12:00:01.000000000 +0000:regular file"
)
OBJECT_IDENTITY = "1:4:1000:600:1:1:regular file"
FILE_DIRECTORY_IDENTITY = FILE_IDENTITY.rsplit(":", 1)[0] + ":directory"
OBJECT_DIRECTORY_IDENTITY = OBJECT_IDENTITY.rsplit(":", 1)[0] + ":directory"
OTHER_DIRECTORY_IDENTITY = "1:20:1000:700:directory"


def test_frozen_csr_recovery_oracle_matches_provenance_and_modes() -> None:
    plan = (ROOT / "docs/plans/platform-pki-python-migration.md").read_text(
        encoding="utf-8"
    )
    assert ORACLE_COMMIT in plan
    assert {
        path.relative_to(ORACLE_ROOT).as_posix()
        for path in ORACLE_ROOT.rglob("*")
    } == {"lib", *ORACLE_HASHES}
    for relative, expected in ORACLE_HASHES.items():
        path = ORACLE_ROOT / relative
        assert path.is_file() and not path.is_symlink()
        assert hashlib.sha256(path.read_bytes()).hexdigest() == expected
        mode = stat.S_IMODE(path.stat().st_mode)
        if relative.startswith("lib/"):
            assert mode == 0o644
        else:
            assert mode == 0o755
            assert os.access(path, os.X_OK)


def _payload(
    fields: tuple[str, ...], values: dict[str, str], *, newline: bool = True
) -> bytes:
    text = "\n".join(f"{field}={values[field]}" for field in fields)
    return (text + ("\n" if newline else "")).encode("ascii")


def _signing_values(*, full_db: bool = False) -> dict[str, str]:
    request_id = "0123456789abcdef0123456789abcdef"
    nonce = "ab" * 32
    transaction = f"csr-{request_id}"
    transaction_dir = f"{PKI_DIR}/state/csr/transactions/{transaction}"
    signing_dir = f"{transaction_dir}/signing"
    values = {field: "none" for field in CSR_SIGNING_JOURNAL_FIELDS}
    values.update(
        schema="1",
        operation="csr-sign",
        transaction=transaction,
        phase="planned",
        committed="false",
        recovery_step="signing-ready" if full_db else "planned",
        request_id=request_id,
        nonce=nonce,
        operation_kind="issue",
        service="External_1",
        target="host-01.example",
        requester_principal="host-01.example",
        approver_principal="pki-approver",
        response_principal="pki-response",
        request_sha256=DIGEST,
        approval_sha256=DIGEST,
        inventory_sha256=DIGEST,
        csr_sha256=DIGEST,
        csr_spki_sha256=DIGEST,
        current_cert_sha256="none",
        created_epoch="0",
        transaction_dir=transaction_dir,
        response_trust_path=f"{transaction_dir}/responses.allowed_signers",
        sensitive_key_path=f"{signing_dir}/private/intermediate-ca.key",
        sensitive_key_removed="none",
        candidate_stage=f"{transaction_dir}/candidate.publish",
        candidate_destination=(
            f"{PKI_DIR}/state/csr/candidates/External_1/{request_id}"
        ),
        response_stage=f"{transaction_dir}/response.publish",
        response_destination=(
            f"{PKI_DIR}/state/csr/responses/External_1/{request_id}"
        ),
        replay_request_path=f"{PKI_DIR}/state/csr/replay/requests/{request_id}",
        replay_nonce_path=f"{PKI_DIR}/state/csr/replay/nonces/{nonce}",
    )
    if not full_db:
        return values

    values.update(
        transaction_identity=DIRECTORY_IDENTITY,
        response_trust_identity=FILE_IDENTITY,
        response_trust_sha256=DIGEST,
        sensitive_key_identity=FILE_IDENTITY,
        replay_request_identity=FILE_IDENTITY,
        replay_request_sha256=DIGEST,
        replay_nonce_identity=FILE_IDENTITY,
        replay_nonce_sha256=DIGEST,
    )
    serial = "10AF"
    authority = f"{PKI_DIR}/authorities/intermediates/g1-i1"
    for index, (key, template) in enumerate(CSR_DB_PATHS):
        relative = template.format(serial=serial)
        pre = "absent" if index % 2 else FILE_IDENTITY
        values.update(
            {
                f"db_{key}_path": f"{authority}/{relative}",
                f"db_{key}_pre_identity": pre,
                f"db_{key}_source": f"{signing_dir}/{relative}",
                f"db_{key}_source_identity": "none",
                f"db_{key}_source_object": "none",
                f"db_{key}_post_identity": "none",
                f"db_{key}_backup": f"{transaction_dir}/ca-backup/{key}",
                f"db_{key}_backup_identity": (
                    "none" if pre == "absent" else FILE_IDENTITY
                ),
            }
        )
    return values


def _set_db_sources(values: dict[str, str], *, present: bool) -> None:
    for key in CSR_DB_KEYS:
        values[f"db_{key}_source_identity"] = FILE_IDENTITY if present else "none"
        values[f"db_{key}_source_object"] = OBJECT_IDENTITY if present else "none"


def _set_db_post_prefix(values: dict[str, str], count: int) -> None:
    for index, key in enumerate(CSR_DB_KEYS):
        values[f"db_{key}_post_identity"] = FILE_IDENTITY if index < count else "none"


def _set_replay_evidence(values: dict[str, str], *, present: bool) -> None:
    for prefix in ("replay_request", "replay_nonce"):
        values[f"{prefix}_identity"] = FILE_IDENTITY if present else "none"
        values[f"{prefix}_sha256"] = DIGEST if present else "none"


def _set_transaction_evidence(values: dict[str, str], *, present: bool) -> None:
    values["transaction_identity"] = DIRECTORY_IDENTITY if present else "none"


def _set_trust_evidence(values: dict[str, str], *, present: bool) -> None:
    values["response_trust_identity"] = FILE_IDENTITY if present else "none"
    values["response_trust_sha256"] = DIGEST if present else "none"


def _set_artifact_evidence(values: dict[str, str], *, present: bool) -> None:
    signing_dir = f'{values["transaction_dir"]}/signing'
    for prefix, name in (
        ("certificate", "tls.crt"),
        ("chain", "ca-chain.crt"),
        ("fullchain", "fullchain.crt"),
        ("response_manifest", "response"),
    ):
        values[f"{prefix}_path"] = f"{signing_dir}/{name}" if present else "none"
        values[f"{prefix}_identity"] = FILE_IDENTITY if present else "none"
        values[f"{prefix}_sha256"] = DIGEST if present else "none"


def _set_signature_path(values: dict[str, str], *, present: bool) -> None:
    values["response_signature_path"] = (
        f'{values["transaction_dir"]}/signing/response.sig' if present else "none"
    )


def _set_signature_evidence(values: dict[str, str], *, present: bool) -> None:
    values["response_signature_identity"] = FILE_IDENTITY if present else "none"
    values["response_signature_sha256"] = DIGEST if present else "none"


def _set_publication_evidence(
    values: dict[str, str],
    publication: tuple[bool, bool, bool, bool],
) -> None:
    for field, present in zip(
        (
            "candidate_stage_identity",
            "candidate_destination_identity",
            "response_stage_identity",
            "response_destination_identity",
        ),
        publication,
        strict=True,
    ):
        values[field] = DIRECTORY_IDENTITY if present else "none"


def _signing_state_values(
    phase: SigningPhase,
    committed: bool,
    step: SigningRecoveryStep,
    *,
    terminal_with_db: bool = True,
) -> dict[str, str]:
    early_steps = {
        SigningRecoveryStep.PLANNED,
        SigningRecoveryStep.REPLAY_RESERVED,
        SigningRecoveryStep.TRANSACTION_STAGED,
    }
    full_db = phase is not SigningPhase.PLANNED or step not in early_steps
    if phase is SigningPhase.TERMINAL and not terminal_with_db:
        full_db = False
    values = _signing_values(full_db=full_db)
    values.update(
        phase=phase.value,
        committed=str(committed).lower(),
        recovery_step=step.value,
    )
    if phase is SigningPhase.TERMINAL:
        values["sensitive_key_removed"] = "true"
        _set_replay_evidence(values, present=True)
        _set_transaction_evidence(values, present=True)
        if committed:
            _set_trust_evidence(values, present=True)
            _set_artifact_evidence(values, present=True)
            _set_signature_path(values, present=True)
            _set_signature_evidence(values, present=True)
            _set_publication_evidence(values, (True, True, True, True))
            _set_db_sources(values, present=True)
            _set_db_post_prefix(values, len(CSR_DB_KEYS))
        elif full_db:
            _set_trust_evidence(values, present=True)
            _set_artifact_evidence(values, present=True)
            _set_signature_path(values, present=True)
            _set_db_sources(values, present=True)
            _set_db_post_prefix(values, len(CSR_DB_KEYS))
        return values
    if phase is SigningPhase.CA_COMMITTED:
        values["sensitive_key_removed"] = "true"
        _set_artifact_evidence(values, present=True)
        _set_signature_path(values, present=True)
        if step is not SigningRecoveryStep.CA_COMMITTED:
            _set_signature_evidence(values, present=True)
        if step is SigningRecoveryStep.CANDIDATE_PUBLISHED:
            _set_publication_evidence(values, (True, True, True, False))
        elif step is SigningRecoveryStep.RESPONSE_PUBLISHED:
            _set_publication_evidence(values, (True, True, True, True))
        _set_db_sources(values, present=True)
        _set_db_post_prefix(values, len(CSR_DB_KEYS))
        return values
    index = SIGNING_PLANNED_STEPS.index(step)
    if index >= SIGNING_PLANNED_STEPS.index(SigningRecoveryStep.REPLAY_RESERVED):
        _set_replay_evidence(values, present=True)
    if index >= SIGNING_PLANNED_STEPS.index(SigningRecoveryStep.TRANSACTION_STAGED):
        _set_transaction_evidence(values, present=True)
        _set_trust_evidence(values, present=True)
    if step is SigningRecoveryStep.SIGNING_COMPLETE:
        _set_artifact_evidence(values, present=True)
        _set_signature_path(values, present=True)
        _set_db_sources(values, present=True)
    elif step not in early_steps and step is not SigningRecoveryStep.SIGNING_READY:
        values["sensitive_key_removed"] = "true"
        _set_artifact_evidence(values, present=True)
        _set_signature_path(values, present=True)
        _set_db_sources(values, present=True)
        if step.value.startswith("ca-"):
            post_steps = SIGNING_PLANNED_STEPS[
                SIGNING_PLANNED_STEPS.index(SigningRecoveryStep.CA_INDEX_PUBLISHED) :
            ]
            _set_db_post_prefix(values, post_steps.index(step) + 1)
    return values


CORE_SIGNING_EVIDENCE_GROUPS = (
    "replay",
    "transaction",
    "trust",
    "sensitive_key",
    "sensitive_key_removed",
    "artifacts",
    "signature_path",
    "signature",
)


def _signing_evidence_group_present(values: dict[str, str], group: str) -> bool:
    if group == "sensitive_key_removed":
        return values["sensitive_key_removed"] == "true"
    fields = {
        "replay": ("replay_request_identity", "replay_nonce_identity"),
        "transaction": ("transaction_identity",),
        "trust": ("response_trust_identity",),
        "sensitive_key": ("sensitive_key_identity",),
        "artifacts": ("certificate_identity", "response_manifest_identity"),
        "signature_path": ("response_signature_path",),
        "signature": ("response_signature_identity",),
    }[group]
    states = {values[field] != "none" for field in fields}
    assert len(states) == 1
    return states.pop()


def _set_signing_evidence_group(
    values: dict[str, str], group: str, *, present: bool
) -> None:
    if group == "replay":
        _set_replay_evidence(values, present=present)
    elif group == "transaction":
        _set_transaction_evidence(values, present=present)
    elif group == "trust":
        _set_trust_evidence(values, present=present)
    elif group == "sensitive_key":
        values["sensitive_key_identity"] = FILE_IDENTITY if present else "none"
    elif group == "sensitive_key_removed":
        values["sensitive_key_removed"] = "true" if present else "none"
    elif group == "artifacts":
        _set_artifact_evidence(values, present=present)
    elif group == "signature_path":
        _set_signature_path(values, present=present)
    elif group == "signature":
        _set_signature_evidence(values, present=present)
    else:
        raise AssertionError(f"unknown signing evidence group: {group}")


def _finalization_values(
    *,
    phase: str = "planned",
    mode: str = "create",
) -> dict[str, str]:
    service = "External_1"
    request_id = "0123456789abcdef0123456789abcdef"
    candidate = f"{PKI_DIR}/state/csr/candidates/{service}/{request_id}"
    response = f"{PKI_DIR}/state/csr/responses/{service}/{request_id}"
    artifact = (
        f"{PKI_DIR}/export/certificates/v1/artifacts/{service}/{request_id}"
    )
    transaction = f"{PKI_DIR}/state/csr/transactions/csr-{request_id}"
    values = {field: DIGEST for field in CANDIDATE_FINALIZATION_JOURNAL_FIELDS}
    values.update(
        schema="1",
        operation="csr-finalize",
        service=service,
        request_id=request_id,
        phase=phase,
        outcome_stage=(
            f"{PKI_DIR}/state/csr/outcomes/{service}/"
            f".platform-pki-csr-outcome.{request_id}.Ab12Z9"
        ),
        outcome_stage_identity=DIRECTORY_IDENTITY,
        outcome_destination=f"{PKI_DIR}/state/csr/outcomes/{service}/{request_id}",
        active_stage=(
            f"{PKI_DIR}/state/csr/active/.platform-pki-active.{service}.Xy90Qp"
        ),
        active_stage_identity=OBJECT_IDENTITY,
        active_destination=f"{PKI_DIR}/state/csr/active/{service}",
        active_pre_identity="absent" if mode == "create" else OBJECT_IDENTITY,
        active_mode=mode,
        active_pre_sha256="none" if mode == "create" else DIGEST,
        candidate_dir=candidate,
        candidate_dir_identity=DIRECTORY_IDENTITY,
        candidate_path=f"{candidate}/candidate",
        candidate_identity=FILE_IDENTITY,
        response_dir=response,
        response_dir_identity=DIRECTORY_IDENTITY,
        response_path=f"{response}/response",
        response_identity=FILE_IDENTITY,
        response_signature_path=f"{response}/response.sig",
        response_signature_identity=FILE_IDENTITY,
        artifact_dir=artifact,
        artifact_dir_identity=DIRECTORY_IDENTITY,
        artifact_path=f"{artifact}/artifact",
        artifact_identity=FILE_IDENTITY,
        transaction_dir=transaction,
        transaction_dir_identity=DIRECTORY_IDENTITY,
        response_trust_path=f"{transaction}/responses.allowed_signers",
        response_trust_identity=FILE_IDENTITY,
        outcome_deployment_identity=FILE_IDENTITY,
        outcome_deployment_signature_identity=FILE_IDENTITY,
        outcome_deployers_identity=FILE_IDENTITY,
        outcome_decision_identity=FILE_IDENTITY,
    )
    for key in CANDIDATE_SOURCE_KEYS:
        values[f"source_{key}_identity"] = FILE_IDENTITY
    if phase == "planned":
        values["outcome_destination_identity"] = "none"
        values["active_destination_identity"] = "none"
    elif phase == "outcome-published":
        values["outcome_destination_identity"] = DIRECTORY_IDENTITY
        values["active_destination_identity"] = "none"
    else:
        values["outcome_destination_identity"] = DIRECTORY_IDENTITY
        values["active_destination_identity"] = OBJECT_IDENTITY
    return values


def test_field_groups_have_exact_authoritative_counts_and_order() -> None:
    assert CSR_DB_KEYS == tuple(key for key, _path in CSR_DB_PATHS)
    assert len(CSR_SIGNING_FIXED_FIELDS) == 58
    assert CSR_SIGNING_JOURNAL_FIELDS == CSR_SIGNING_FIXED_FIELDS + tuple(
        f"db_{key}_{suffix}" for key in CSR_DB_KEYS for suffix in CSR_DB_SUFFIXES
    )
    assert len(CSR_SIGNING_JOURNAL_FIELDS) == 114
    assert len(set(CSR_SIGNING_JOURNAL_FIELDS)) == 114

    assert CANDIDATE_SOURCE_KEYS == tuple(
        key for key, _root, _name in CANDIDATE_SOURCE_PATHS
    )
    assert len(CANDIDATE_SOURCE_KEYS) == 17
    assert len(CANDIDATE_FINALIZATION_FIXED_FIELDS) == 48
    assert CANDIDATE_FINALIZATION_JOURNAL_FIELDS == (
        CANDIDATE_FINALIZATION_FIXED_FIELDS
        + tuple(
            f"source_{key}_{suffix}"
            for key in CANDIDATE_SOURCE_KEYS
            for suffix in ("identity", "sha256")
        )
    )
    assert len(CANDIDATE_FINALIZATION_JOURNAL_FIELDS) == 82
    assert len(set(CANDIDATE_FINALIZATION_JOURNAL_FIELDS)) == 82


def test_migration_contract_reexports_python_authoritative_fields() -> None:
    from tests.pki import migration_contract

    assert migration_contract.CSR_DB_KEYS is CSR_DB_KEYS
    assert migration_contract.CSR_JOURNAL_FIELDS is CSR_SIGNING_JOURNAL_FIELDS
    assert migration_contract.CANDIDATE_SOURCE_KEYS is CANDIDATE_SOURCE_KEYS
    assert (
        migration_contract.CANDIDATE_JOURNAL_FIELDS
        is CANDIDATE_FINALIZATION_JOURNAL_FIELDS
    )


def test_signing_structure_accepts_optional_newline_and_empty_values() -> None:
    values = {field: "value" for field in CSR_SIGNING_JOURNAL_FIELDS}
    values.update(schema="1", operation="csr-sign", approver_principal="")
    with_newline = parse_signing_journal_structure(
        _payload(CSR_SIGNING_JOURNAL_FIELDS, values)
    )
    without_newline = parse_signing_journal_structure(
        _payload(CSR_SIGNING_JOURNAL_FIELDS, values, newline=False)
    )
    assert with_newline.final_newline is True
    assert without_newline.final_newline is False
    assert with_newline["approver_principal"] == without_newline["approver_principal"] == ""


def test_finalization_structure_requires_nonempty_values_and_one_newline() -> None:
    values = {field: "value" for field in CANDIDATE_FINALIZATION_JOURNAL_FIELDS}
    values.update(schema="1", operation="csr-finalize")
    assert parse_finalization_journal_structure(
        _payload(CANDIDATE_FINALIZATION_JOURNAL_FIELDS, values)
    ).final_newline
    with pytest.raises(CsrRecoveryError, match="one newline"):
        parse_finalization_journal_structure(
            _payload(CANDIDATE_FINALIZATION_JOURNAL_FIELDS, values, newline=False)
        )
    values["service"] = ""
    with pytest.raises(CsrRecoveryError, match="empty"):
        parse_finalization_journal_structure(
            _payload(CANDIDATE_FINALIZATION_JOURNAL_FIELDS, values)
        )


def test_journal_newline_rules_match_the_shell_readers() -> None:
    signing_source = (ROOT / "lib/platform-pki-csr-sign.sh").read_text(
        encoding="utf-8"
    )
    signing_reader = signing_source[
        signing_source.index("pki_csr_read_journal()") :
        signing_source.index("pki_csr_require_journal_path()")
    ]
    assert 'while IFS= read -r -u "$fd" line || [[ -n $line ]]; do' in signing_reader

    candidate_source = (ROOT / "lib/platform-pki-csr-candidate.sh").read_text(
        encoding="utf-8"
    )
    candidate_reader = candidate_source[candidate_source.index("pki_candidate_recover()") :]
    assert "pki_csr_read_ordered_record" in candidate_reader
    assert (
        '[[ $(wc -l <"$journal") -eq ${#PKI_CANDIDATE_JOURNAL_FIELDS[@]} ]]'
        in candidate_reader
    )


def test_signing_evidence_order_matches_the_shell_writer_and_recovery_rewrites() -> None:
    source = (ROOT / "lib/platform-pki-csr-sign.sh").read_text(encoding="utf-8")
    external = source[
        source.index("pki_csr_sign_external()") : source.index("pki_csr_recover()")
    ]
    ordered_fragments = (
        "pki_csr_write_journal; CSR_JOURNAL_STARTED=true",
        "pki_csr_ensure_replay; pki_csr_checkpoint replay-reserved",
        "CSR_JOURNAL[transaction_identity]=",
        "CSR_JOURNAL[response_trust_identity]=",
        "pki_csr_checkpoint transaction-staged",
        "CSR_JOURNAL[sensitive_key_identity]=",
        "pki_csr_checkpoint signing-ready",
        "CSR_JOURNAL[certificate_path]=",
        "CSR_JOURNAL[response_manifest_path]=",
        "CSR_JOURNAL[db_${key}_source_identity]=",
        "pki_csr_checkpoint signing-complete",
        "pki_csr_remove_sensitive_key; pki_csr_checkpoint sensitive-key-removed",
        "CSR_JOURNAL[db_${key}_post_identity]=",
        'pki_csr_checkpoint "ca-$key-published"',
        "CSR_JOURNAL[committed]=true; CSR_JOURNAL[phase]=ca-committed",
        "pki_csr_checkpoint ca-committed",
    )
    positions = tuple(external.index(fragment) for fragment in ordered_fragments)
    assert positions == tuple(sorted(positions))

    response_signing = source[
        source.index("pki_csr_sign_response()") : source.index(
            "pki_csr_validate_artifact_entries()"
        )
    ]
    assert response_signing.index("CSR_JOURNAL[response_signature_identity]=") < (
        response_signing.index("pki_csr_checkpoint response-signed")
    )
    stage_preparation = source[
        source.index("pki_csr_prepare_artifact()") : source.index(
            "pki_csr_validate_published_artifact()"
        )
    ]
    assert stage_preparation.index("CSR_JOURNAL[$identity_field]=$expected") < (
        stage_preparation.index("pki_csr_write_journal")
    )
    publication = source[
        source.index("pki_csr_publish_artifact()") : source.index(
            "pki_csr_resume_committed()"
        )
    ]
    assert publication.count("pki_csr_write_journal") == 2
    assert "CSR_JOURNAL[$identity_field]=$PKI_CSR_VALIDATED_ARTIFACT_IDENTITY" in publication
    assert "pki_csr_publish_artifact candidate; pki_csr_checkpoint candidate-published" in source
    assert "pki_csr_publish_artifact response; pki_csr_checkpoint response-published" in source
    assert "CSR_JOURNAL[phase]=terminal" in source
    assert "CSR_JOURNAL[recovery_step]=journal-cleanup-pending" in source


@pytest.mark.parametrize(
    "mutation,diagnostic",
    (
        (lambda lines: [*lines, lines[0]], "extra|duplicate"),
        (lambda lines: [*lines[:-1], lines[0]], "duplicate"),
        (lambda lines: lines[:-1], "missing"),
        (lambda lines: [lines[1], lines[0], *lines[2:]], "reordered"),
        (lambda lines: [lines[0].replace(b"=", b"", 1), *lines[1:]], "malformed"),
        (lambda lines: [lines[0] + b"\x01", *lines[1:]], "non-ASCII"),
        (lambda lines: [lines[0] + b"\xff", *lines[1:]], "non-ASCII"),
    ),
)
def test_structural_parsers_reject_malformed_records(mutation, diagnostic: str) -> None:
    values = _signing_values()
    lines = _payload(CSR_SIGNING_JOURNAL_FIELDS, values).rstrip(b"\n").split(b"\n")
    changed = b"\n".join(mutation(lines)) + b"\n"
    with pytest.raises(CsrRecoveryError, match=diagnostic):
        parse_signing_journal_structure(changed)


@pytest.mark.parametrize("extra", (b"\n", b"\nblank=value\n"))
def test_structural_parsers_reject_blank_or_extra_records(extra: bytes) -> None:
    values = _signing_values()
    with pytest.raises(CsrRecoveryError):
        parse_signing_journal_structure(
            _payload(CSR_SIGNING_JOURNAL_FIELDS, values) + extra
        )


def test_signing_none_database_variant_is_typed_and_immutable() -> None:
    journal = parse_signing_journal(
        _payload(CSR_SIGNING_JOURNAL_FIELDS, _signing_values()),
        pki_dir=PKI_DIR,
    )
    assert journal.phase is SigningPhase.PLANNED
    assert journal.issued_serial is None
    assert journal.journal_intermediate_dir is None
    assert journal.identity("transaction_identity") is IdentitySentinel.NONE
    assert journal.path("certificate_path") is None
    validate_signing_transaction_presence(journal, transaction_exists=False)
    with pytest.raises(CsrRecoveryError, match="unowned"):
        validate_signing_transaction_presence(journal, transaction_exists=True)
    with pytest.raises(FrozenInstanceError):
        journal.committed = True  # type: ignore[misc]


def test_signing_full_database_variant_maps_all_seven_paths_and_identity_kinds() -> None:
    values = _signing_values(full_db=True)
    journal = parse_signing_journal(
        _payload(CSR_SIGNING_JOURNAL_FIELDS, values, newline=False),
        pki_dir=PKI_DIR,
    )
    assert journal.issued_serial == "10AF"
    assert journal.journal_intermediate_dir == (
        f"{PKI_DIR}/authorities/intermediates/g1-i1"
    )
    for index, (key, template) in enumerate(CSR_DB_PATHS):
        relative = template.format(serial="10AF")
        assert journal.path(f"db_{key}_path") == (
            f"{PKI_DIR}/authorities/intermediates/g1-i1/{relative}"
        )
        source = journal.path(f"db_{key}_source")
        backup = journal.path(f"db_{key}_backup")
        assert source is not None and source.endswith(f"/signing/{relative}")
        assert backup is not None and backup.endswith(f"/ca-backup/{key}")
        pre = journal.identity(f"db_{key}_pre_identity")
        if index % 2 == 0:
            assert isinstance(pre, FileIdentity)
        else:
            assert pre is IdentitySentinel.ABSENT
        assert journal.identity(f"db_{key}_source_identity") is IdentitySentinel.NONE
        assert journal.identity(f"db_{key}_source_object") is IdentitySentinel.NONE


def test_signing_journal_authority_is_journal_derived_and_optionally_context_bound() -> None:
    values = _signing_values(full_db=True)
    expected = f"{PKI_DIR}/authorities/intermediates/g1-i1"
    journal = parse_signing_journal(
        _payload(CSR_SIGNING_JOURNAL_FIELDS, values),
        pki_dir=PKI_DIR,
        active_intermediate_dir=expected,
    )
    assert journal.journal_intermediate_dir == expected

    alternate = f"{PKI_DIR}/authorities/intermediates/g9-i7"
    alternate_values = {
        field: value.replace(expected, alternate) for field, value in values.items()
    }
    assert parse_signing_journal(
        _payload(CSR_SIGNING_JOURNAL_FIELDS, alternate_values),
        pki_dir=PKI_DIR,
    ).journal_intermediate_dir == alternate
    with pytest.raises(CsrRecoveryError, match="active intermediate"):
        parse_signing_journal(
            _payload(CSR_SIGNING_JOURNAL_FIELDS, alternate_values),
            pki_dir=PKI_DIR,
            active_intermediate_dir=expected,
        )


@pytest.mark.parametrize("serial", ("A", "abc0", "0G", "ABC", "00AF"))
def test_signing_rejects_nonuppercase_or_odd_issued_serial(serial: str) -> None:
    values = _signing_values(full_db=True)
    original = "10AF"
    for field in tuple(values):
        values[field] = values[field].replace(original, serial)
    with pytest.raises(CsrRecoveryError, match="serial"):
        parse_signing_journal(
            _payload(CSR_SIGNING_JOURNAL_FIELDS, values), pki_dir=PKI_DIR
        )


@pytest.mark.parametrize("serial", ("00", "01", "FF", "0100"))
def test_signing_accepts_canonical_issued_serial_boundaries(serial: str) -> None:
    values = _signing_values(full_db=True)
    for field in tuple(values):
        values[field] = values[field].replace("10AF", serial)
    journal = parse_signing_journal(
        _payload(CSR_SIGNING_JOURNAL_FIELDS, values), pki_dir=PKI_DIR
    )
    assert journal.issued_serial == serial
    assert journal.record["db_newcert_path"].endswith(
        f"/newcerts/{serial}.pem"
    )


def test_signing_rejects_partial_db_contract_wrong_identity_kind_and_sentinel() -> None:
    values = _signing_values()
    values["db_serial_path"] = "/tmp/serial"
    with pytest.raises(CsrRecoveryError, match="partial DB"):
        parse_signing_journal(
            _payload(CSR_SIGNING_JOURNAL_FIELDS, values), pki_dir=PKI_DIR
        )

    values = _signing_values(full_db=True)
    values["db_index_pre_identity"] = OBJECT_IDENTITY
    with pytest.raises(CsrRecoveryError, match="db_index_pre_identity"):
        parse_signing_journal(
            _payload(CSR_SIGNING_JOURNAL_FIELDS, values), pki_dir=PKI_DIR
        )
    values = _signing_values(full_db=True)
    values["db_index_pre_identity"] = "none"
    with pytest.raises(CsrRecoveryError, match="sentinel"):
        parse_signing_journal(
            _payload(CSR_SIGNING_JOURNAL_FIELDS, values), pki_dir=PKI_DIR
        )


VALID_SIGNING_STATE_VALUES = frozenset(
    {
        *(
            ("planned", "false", step)
            for step in (
                "planned",
                "replay-reserved",
                "transaction-staged",
                "signing-ready",
                "signing-complete",
                "sensitive-key-removed",
                "ca-index-published",
                "ca-index_attr-published",
                "ca-serial-published",
                "ca-index_old-published",
                "ca-index_attr_old-published",
                "ca-serial_old-published",
                "ca-newcert-published",
            )
        ),
        *(
            ("ca-committed", "true", step)
            for step in (
                "ca-committed",
                "response-signed",
                "candidate-published",
                "response-published",
            )
        ),
        ("terminal", "false", "journal-cleanup-pending"),
        ("terminal", "true", "journal-cleanup-pending"),
    }
)


@pytest.mark.parametrize("phase", tuple(SigningPhase))
@pytest.mark.parametrize("committed", (False, True))
@pytest.mark.parametrize("step", tuple(SigningRecoveryStep))
def test_signing_accepts_only_the_exact_phase_commit_checkpoint_matrix(
    phase: SigningPhase,
    committed: bool,
    step: SigningRecoveryStep,
) -> None:
    state = (phase.value, str(committed).lower(), step.value)
    if state in VALID_SIGNING_STATE_VALUES:
        values = _signing_state_values(phase, committed, step)
        journal = parse_signing_journal(
            _payload(CSR_SIGNING_JOURNAL_FIELDS, values), pki_dir=PKI_DIR
        )
        assert (
            journal.phase,
            journal.committed,
            journal.recovery_step,
        ) == (phase, committed, step)
        return

    values = _signing_values()
    values.update(
        phase=phase.value,
        committed=str(committed).lower(),
        recovery_step=step.value,
    )
    with pytest.raises(CsrRecoveryError, match="phase, committed state, and recovery step"):
        parse_signing_journal(
            _payload(CSR_SIGNING_JOURNAL_FIELDS, values), pki_dir=PKI_DIR
        )


@pytest.mark.parametrize("state", sorted(VALID_SIGNING_STATE_VALUES))
@pytest.mark.parametrize("group", CORE_SIGNING_EVIDENCE_GROUPS)
def test_signing_checkpoint_boundaries_reject_missing_or_premature_core_evidence(
    state: tuple[str, str, str], group: str
) -> None:
    phase_value, committed_value, step_value = state
    values = _signing_state_values(
        SigningPhase(phase_value),
        committed_value == "true",
        SigningRecoveryStep(step_value),
    )
    present = _signing_evidence_group_present(values, group)
    _set_signing_evidence_group(values, group, present=not present)
    with pytest.raises(CsrRecoveryError):
        parse_signing_journal(
            _payload(CSR_SIGNING_JOURNAL_FIELDS, values), pki_dir=PKI_DIR
        )


PUBLICATION_STATES = tuple(product((False, True), repeat=4))


def _allowed_publication_states(
    phase: SigningPhase,
    committed: bool,
    step: SigningRecoveryStep,
) -> frozenset[tuple[bool, bool, bool, bool]]:
    none = (False, False, False, False)
    complete = (True, True, True, True)
    if phase is SigningPhase.PLANNED:
        return frozenset((none,))
    if phase is SigningPhase.TERMINAL:
        return frozenset((complete if committed else none,))
    if step is SigningRecoveryStep.CA_COMMITTED:
        return frozenset((none,))
    if step is SigningRecoveryStep.RESPONSE_SIGNED:
        return frozenset(
            (
                none,
                (True, False, False, False),
                (True, False, True, False),
                (True, True, True, False),
            )
        )
    if step is SigningRecoveryStep.CANDIDATE_PUBLISHED:
        return frozenset(
            ((True, True, True, False), (True, True, True, True))
        )
    return frozenset((complete,))


@pytest.mark.parametrize("state", sorted(VALID_SIGNING_STATE_VALUES))
@pytest.mark.parametrize("publication", PUBLICATION_STATES)
def test_signing_checkpoint_boundaries_accept_only_durable_publication_rewrites(
    state: tuple[str, str, str],
    publication: tuple[bool, bool, bool, bool],
) -> None:
    phase_value, committed_value, step_value = state
    phase = SigningPhase(phase_value)
    committed = committed_value == "true"
    step = SigningRecoveryStep(step_value)
    values = _signing_state_values(phase, committed, step)
    _set_publication_evidence(values, publication)
    if publication in _allowed_publication_states(phase, committed, step):
        parse_signing_journal(
            _payload(CSR_SIGNING_JOURNAL_FIELDS, values), pki_dir=PKI_DIR
        )
    else:
        with pytest.raises(CsrRecoveryError):
            parse_signing_journal(
                _payload(CSR_SIGNING_JOURNAL_FIELDS, values), pki_dir=PKI_DIR
            )


@pytest.mark.parametrize(
    "level",
    ("initial", "transaction-staged", "signing-ready", "signing-complete"),
)
def test_terminal_uncommitted_recovery_accepts_each_durable_evidence_prefix(
    level: str,
) -> None:
    full_db = level in {"signing-ready", "signing-complete"}
    values = _signing_state_values(
        SigningPhase.TERMINAL,
        False,
        SigningRecoveryStep.JOURNAL_CLEANUP_PENDING,
        terminal_with_db=full_db,
    )
    if level == "transaction-staged":
        _set_trust_evidence(values, present=True)
    elif level == "signing-ready":
        _set_db_sources(values, present=False)
        _set_db_post_prefix(values, 0)
        _set_artifact_evidence(values, present=False)
        _set_signature_path(values, present=False)
    parse_signing_journal(
        _payload(CSR_SIGNING_JOURNAL_FIELDS, values), pki_dir=PKI_DIR
    )


@pytest.mark.parametrize(
    ("step", "field"),
    (
        (SigningRecoveryStep.REPLAY_RESERVED, "replay_request_identity"),
        (SigningRecoveryStep.REPLAY_RESERVED, "replay_request_sha256"),
        (SigningRecoveryStep.REPLAY_RESERVED, "replay_nonce_identity"),
        (SigningRecoveryStep.REPLAY_RESERVED, "replay_nonce_sha256"),
        (SigningRecoveryStep.TRANSACTION_STAGED, "response_trust_identity"),
        (SigningRecoveryStep.TRANSACTION_STAGED, "response_trust_sha256"),
        *(
            (SigningRecoveryStep.SIGNING_COMPLETE, f"{prefix}_{suffix}")
            for prefix in (
                "certificate",
                "chain",
                "fullchain",
                "response_manifest",
            )
            for suffix in ("path", "identity", "sha256")
        ),
        (SigningRecoveryStep.RESPONSE_SIGNED, "response_signature_identity"),
        (SigningRecoveryStep.RESPONSE_SIGNED, "response_signature_sha256"),
    ),
)
def test_signing_checkpoint_evidence_pairs_reject_partial_records(
    step: SigningRecoveryStep, field: str
) -> None:
    phase = (
        SigningPhase.PLANNED
        if step in SIGNING_PLANNED_STEPS
        else SigningPhase.CA_COMMITTED
    )
    values = _signing_state_values(
        phase, phase is SigningPhase.CA_COMMITTED, step
    )
    values[field] = "none"
    with pytest.raises(CsrRecoveryError):
        parse_signing_journal(
            _payload(CSR_SIGNING_JOURNAL_FIELDS, values), pki_dir=PKI_DIR
        )


@pytest.mark.parametrize(
    "fields",
    (
        ("replay_request_identity", "replay_request_sha256"),
        ("replay_nonce_identity", "replay_nonce_sha256"),
        ("certificate_path", "certificate_identity", "certificate_sha256"),
        ("chain_path", "chain_identity", "chain_sha256"),
        ("fullchain_path", "fullchain_identity", "fullchain_sha256"),
        (
            "response_manifest_path",
            "response_manifest_identity",
            "response_manifest_sha256",
        ),
    ),
)
def test_signing_checkpoint_evidence_groups_reject_one_missing_complete_pair(
    fields: tuple[str, ...],
) -> None:
    step = (
        SigningRecoveryStep.REPLAY_RESERVED
        if fields[0].startswith("replay_")
        else SigningRecoveryStep.SIGNING_COMPLETE
    )
    values = _signing_state_values(SigningPhase.PLANNED, False, step)
    for field in fields:
        values[field] = "none"
    with pytest.raises(CsrRecoveryError, match="evidence is incomplete"):
        parse_signing_journal(
            _payload(CSR_SIGNING_JOURNAL_FIELDS, values), pki_dir=PKI_DIR
        )


def test_signing_publication_destination_identity_must_equal_its_stage() -> None:
    values = _signing_state_values(
        SigningPhase.CA_COMMITTED,
        True,
        SigningRecoveryStep.CANDIDATE_PUBLISHED,
    )
    values["candidate_destination_identity"] = OTHER_DIRECTORY_IDENTITY
    with pytest.raises(CsrRecoveryError, match="stage and destination differ"):
        parse_signing_journal(
            _payload(CSR_SIGNING_JOURNAL_FIELDS, values), pki_dir=PKI_DIR
        )


def test_signing_enforces_database_evidence_checkpoint_windows() -> None:
    ready = _signing_state_values(
        SigningPhase.PLANNED, False, SigningRecoveryStep.SIGNING_READY
    )
    parse_signing_journal(
        _payload(CSR_SIGNING_JOURNAL_FIELDS, ready), pki_dir=PKI_DIR
    )
    ready["db_index_source_identity"] = FILE_IDENTITY
    ready["db_index_source_object"] = OBJECT_IDENTITY
    with pytest.raises(CsrRecoveryError, match="source evidence is incomplete"):
        parse_signing_journal(
            _payload(CSR_SIGNING_JOURNAL_FIELDS, ready), pki_dir=PKI_DIR
        )

    complete = _signing_state_values(
        SigningPhase.PLANNED, False, SigningRecoveryStep.SIGNING_COMPLETE
    )
    _set_db_sources(complete, present=False)
    with pytest.raises(CsrRecoveryError, match="source evidence conflicts"):
        parse_signing_journal(
            _payload(CSR_SIGNING_JOURNAL_FIELDS, complete), pki_dir=PKI_DIR
        )

    published = _signing_state_values(
        SigningPhase.PLANNED, False, SigningRecoveryStep.CA_SERIAL_PUBLISHED
    )
    published["db_index_attr_post_identity"] = "none"
    with pytest.raises(CsrRecoveryError, match="not a prefix"):
        parse_signing_journal(
            _payload(CSR_SIGNING_JOURNAL_FIELDS, published), pki_dir=PKI_DIR
        )
    published = _signing_state_values(
        SigningPhase.PLANNED, False, SigningRecoveryStep.CA_SERIAL_PUBLISHED
    )
    published["db_index_old_post_identity"] = FILE_IDENTITY
    with pytest.raises(CsrRecoveryError, match="checkpoint"):
        parse_signing_journal(
            _payload(CSR_SIGNING_JOURNAL_FIELDS, published), pki_dir=PKI_DIR
        )

    terminal_without_db = _signing_state_values(
        SigningPhase.TERMINAL,
        False,
        SigningRecoveryStep.JOURNAL_CLEANUP_PENDING,
        terminal_with_db=False,
    )
    parse_signing_journal(
        _payload(CSR_SIGNING_JOURNAL_FIELDS, terminal_without_db), pki_dir=PKI_DIR
    )
    terminal_with_unsigned_sources = _signing_state_values(
        SigningPhase.TERMINAL,
        False,
        SigningRecoveryStep.JOURNAL_CLEANUP_PENDING,
    )
    _set_db_sources(terminal_with_unsigned_sources, present=False)
    _set_db_post_prefix(terminal_with_unsigned_sources, 0)
    parse_signing_journal(
        _payload(CSR_SIGNING_JOURNAL_FIELDS, terminal_with_unsigned_sources),
        pki_dir=PKI_DIR,
    )


def test_signing_enforces_sensitive_key_evidence_checkpoint_windows() -> None:
    values = _signing_values()
    values["sensitive_key_identity"] = FILE_IDENTITY
    with pytest.raises(CsrRecoveryError, match="sensitive-key evidence"):
        parse_signing_journal(
            _payload(CSR_SIGNING_JOURNAL_FIELDS, values), pki_dir=PKI_DIR
        )

    values = _signing_state_values(
        SigningPhase.PLANNED, False, SigningRecoveryStep.SIGNING_READY
    )
    values["sensitive_key_identity"] = "none"
    with pytest.raises(CsrRecoveryError, match="sensitive-key evidence"):
        parse_signing_journal(
            _payload(CSR_SIGNING_JOURNAL_FIELDS, values), pki_dir=PKI_DIR
        )

    values = _signing_state_values(
        SigningPhase.PLANNED, False, SigningRecoveryStep.SENSITIVE_KEY_REMOVED
    )
    values["sensitive_key_removed"] = "none"
    with pytest.raises(CsrRecoveryError, match="sensitive-key evidence"):
        parse_signing_journal(
            _payload(CSR_SIGNING_JOURNAL_FIELDS, values), pki_dir=PKI_DIR
        )

    values = _signing_state_values(
        SigningPhase.TERMINAL,
        False,
        SigningRecoveryStep.JOURNAL_CLEANUP_PENDING,
        terminal_with_db=False,
    )
    values["sensitive_key_identity"] = FILE_IDENTITY
    with pytest.raises(CsrRecoveryError, match="DB and key evidence"):
        parse_signing_journal(
            _payload(CSR_SIGNING_JOURNAL_FIELDS, values), pki_dir=PKI_DIR
        )

    values = _signing_state_values(
        SigningPhase.TERMINAL,
        False,
        SigningRecoveryStep.JOURNAL_CLEANUP_PENDING,
    )
    values["sensitive_key_identity"] = "none"
    with pytest.raises(CsrRecoveryError, match="DB and key evidence"):
        parse_signing_journal(
            _payload(CSR_SIGNING_JOURNAL_FIELDS, values), pki_dir=PKI_DIR
        )


def test_recovery_file_evidence_rejects_directory_object_kinds() -> None:
    values = _signing_values()
    values["response_trust_identity"] = FILE_DIRECTORY_IDENTITY
    values["response_trust_sha256"] = DIGEST
    with pytest.raises(CsrRecoveryError, match="not regular"):
        parse_signing_journal(
            _payload(CSR_SIGNING_JOURNAL_FIELDS, values), pki_dir=PKI_DIR
        )

    values = _signing_state_values(
        SigningPhase.PLANNED, False, SigningRecoveryStep.SIGNING_COMPLETE
    )
    values["db_index_source_object"] = OBJECT_DIRECTORY_IDENTITY
    with pytest.raises(CsrRecoveryError, match="not regular"):
        parse_signing_journal(
            _payload(CSR_SIGNING_JOURNAL_FIELDS, values), pki_dir=PKI_DIR
        )

    values = _finalization_values()
    values["candidate_identity"] = FILE_DIRECTORY_IDENTITY
    values["source_candidate_candidate_identity"] = FILE_DIRECTORY_IDENTITY
    with pytest.raises(CsrRecoveryError, match="not regular"):
        parse_finalization_journal(
            _payload(CANDIDATE_FINALIZATION_JOURNAL_FIELDS, values),
            pki_dir=PKI_DIR,
        )

    values = _finalization_values()
    values["active_stage_identity"] = OBJECT_DIRECTORY_IDENTITY
    with pytest.raises(CsrRecoveryError, match="not regular"):
        parse_finalization_journal(
            _payload(CANDIDATE_FINALIZATION_JOURNAL_FIELDS, values),
            pki_dir=PKI_DIR,
        )


@pytest.mark.parametrize(
    "field,replacement",
    (
        ("transaction_dir", f"{PKI_DIR}/state/csr/transactions/../escape"),
        ("candidate_destination", f"{PKI_DIR}/state/csr/candidates-prefix/External_1/0123456789abcdef0123456789abcdef"),
        ("db_index_path", f"{PKI_DIR}/authorities/intermediates/g1-i1-prefix/index.txt"),
    ),
)
def test_signing_rejects_escape_and_prefix_confusion(field: str, replacement: str) -> None:
    values = _signing_values(full_db=field.startswith("db_"))
    values[field] = replacement
    with pytest.raises(CsrRecoveryError, match=field.split("_path")[0]):
        parse_signing_journal(
            _payload(CSR_SIGNING_JOURNAL_FIELDS, values), pki_dir=PKI_DIR
        )


def test_signing_validates_scalars_digests_booleans_and_phase_coherence() -> None:
    cases = (
        ("request_id", "A" * 32),
        ("nonce", "0" * 63),
        ("operation_kind", "replace"),
        ("target", "Host_01"),
        ("committed", "yes"),
        ("request_sha256", "A" * 64),
        ("created_epoch", "01"),
        ("recovery_step", "unknown-step"),
    )
    for field, replacement in cases:
        values = _signing_values()
        values[field] = replacement
        with pytest.raises(CsrRecoveryError, match=field):
            parse_signing_journal(
                _payload(CSR_SIGNING_JOURNAL_FIELDS, values), pki_dir=PKI_DIR
            )
    values = _signing_values()
    values["committed"] = "true"
    with pytest.raises(CsrRecoveryError, match="phase, committed state"):
        parse_signing_journal(
            _payload(CSR_SIGNING_JOURNAL_FIELDS, values), pki_dir=PKI_DIR
        )


@pytest.mark.parametrize(
    "phase,mode",
    (
        ("planned", "create"),
        ("outcome-published", "exchange"),
        ("active-published", "exchange"),
    ),
)
def test_finalization_types_phases_modes_identities_and_all_source_paths(
    phase: str, mode: str
) -> None:
    journal = parse_finalization_journal(
        _payload(
            CANDIDATE_FINALIZATION_JOURNAL_FIELDS,
            _finalization_values(phase=phase, mode=mode),
        ),
        pki_dir=PKI_DIR,
    )
    assert journal.phase is FinalizationPhase(phase)
    assert journal.active_mode is ActivePublicationMode(mode)
    assert isinstance(journal.identity("candidate_dir_identity"), DirectoryIdentity)
    assert isinstance(journal.identity("candidate_identity"), FileIdentity)
    assert isinstance(journal.identity("active_stage_identity"), FileObjectState)
    assert tuple(key for key, _path in journal.source_paths) == CANDIDATE_SOURCE_KEYS
    for key, source_root, name in CANDIDATE_SOURCE_PATHS:
        assert journal.source_path(key) == f"{journal.path(f'{source_root}_dir')}/{name}"


@pytest.mark.parametrize(
    "field,replacement",
    (
        ("outcome_stage", f"{PKI_DIR}/state/csr/outcomes/External_1/.platform-pki-csr-outcome.0123456789abcdef0123456789abcdef.ABC123/escape"),
        ("outcome_stage", f"{PKI_DIR}/state/csr/outcomes/External_1/.platform-pki-csr-outcome.0123456789abcdef0123456789abcdef-prefix.ABC123"),
        ("active_stage", f"{PKI_DIR}/state/csr/active/.platform-pki-active.External_1.ABC12"),
        ("candidate_dir", f"{PKI_DIR}/state/csr/candidates-prefix/External_1/0123456789abcdef0123456789abcdef"),
        ("response_path", f"{PKI_DIR}/state/csr/responses/External_1/0123456789abcdef0123456789abcdef/../response"),
    ),
)
def test_finalization_rejects_escape_prefix_confusion_and_bad_stage_suffix(
    field: str, replacement: str
) -> None:
    values = _finalization_values()
    values[field] = replacement
    with pytest.raises(CsrRecoveryError, match=field):
        parse_finalization_journal(
            _payload(CANDIDATE_FINALIZATION_JOURNAL_FIELDS, values),
            pki_dir=PKI_DIR,
        )


@pytest.mark.parametrize(
    "field,replacement",
    (
        ("candidate_dir_identity", FILE_IDENTITY),
        ("candidate_identity", OBJECT_IDENTITY),
        ("active_stage_identity", FILE_IDENTITY),
        ("outcome_stage_identity", "none"),
        ("active_stage_identity", "absent"),
        ("source_candidate_tls_crt_identity", "none"),
    ),
)
def test_finalization_rejects_wrong_identity_kinds_and_sentinels(
    field: str, replacement: str
) -> None:
    values = _finalization_values()
    values[field] = replacement
    with pytest.raises(CsrRecoveryError, match=field):
        parse_finalization_journal(
            _payload(CANDIDATE_FINALIZATION_JOURNAL_FIELDS, values),
            pki_dir=PKI_DIR,
        )


def test_finalization_rejects_phase_identity_and_active_mode_contradictions() -> None:
    values = _finalization_values()
    values["outcome_destination_identity"] = DIRECTORY_IDENTITY
    with pytest.raises(CsrRecoveryError, match="phase identities"):
        parse_finalization_journal(
            _payload(CANDIDATE_FINALIZATION_JOURNAL_FIELDS, values),
            pki_dir=PKI_DIR,
        )
    values = _finalization_values(mode="exchange")
    values["active_pre_identity"] = "absent"
    with pytest.raises(CsrRecoveryError, match="exchange mode"):
        parse_finalization_journal(
            _payload(CANDIDATE_FINALIZATION_JOURNAL_FIELDS, values),
            pki_dir=PKI_DIR,
        )
    values = _finalization_values()
    values["active_pre_sha256"] = DIGEST
    with pytest.raises(CsrRecoveryError, match="create mode"):
        parse_finalization_journal(
            _payload(CANDIDATE_FINALIZATION_JOURNAL_FIELDS, values),
            pki_dir=PKI_DIR,
        )


def test_finalization_rejects_invalid_source_digests_and_main_mapping_conflicts() -> None:
    for key, _source_root, _name in CANDIDATE_SOURCE_PATHS:
        values = _finalization_values()
        values[f"source_{key}_sha256"] = "A" * 64
        with pytest.raises(CsrRecoveryError, match=f"source_{key}_sha256"):
            parse_finalization_journal(
                _payload(CANDIDATE_FINALIZATION_JOURNAL_FIELDS, values),
                pki_dir=PKI_DIR,
            )
    values = _finalization_values()
    values["source_candidate_candidate_identity"] = FILE_IDENTITY.replace(
        "1:3:", "1:30:", 1
    )
    with pytest.raises(CsrRecoveryError, match="candidate"):
        parse_finalization_journal(
            _payload(CANDIDATE_FINALIZATION_JOURNAL_FIELDS, values),
            pki_dir=PKI_DIR,
        )
    values = _finalization_values()
    values["source_response_response_sha256"] = "1" * 64
    with pytest.raises(CsrRecoveryError, match="response"):
        parse_finalization_journal(
            _payload(CANDIDATE_FINALIZATION_JOURNAL_FIELDS, values),
            pki_dir=PKI_DIR,
        )


@pytest.mark.parametrize("pki_dir", ("relative/pki", "/srv/platform/pki/../pki", b"/srv/platform/pki"))
def test_semantic_parsers_require_canonical_text_pki_directory(pki_dir) -> None:
    with pytest.raises((CsrRecoveryError, TypeError)):
        parse_signing_journal(
            _payload(CSR_SIGNING_JOURNAL_FIELDS, _signing_values()),
            pki_dir=pki_dir,
        )
