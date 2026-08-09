from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

import pytest

from src.platform_pki import ca_rollover_recovery as recovery
from src.platform_pki.ca_rollover_recovery import (
    GenericRecoveryRecord,
    RecoveryAction,
    RecoveryOperation,
    RecoveryRecordError,
    RecoveryRecordOrder,
    load_recovery_record,
    load_rollover_prepare_structure,
    parse_recovery_action,
    parse_recovery_record,
    parse_rollover_prepare_structure,
    serialize_recovery_rewrite,
)
from src.platform_pki.filesystem import (
    DirectoryIdentity,
    FileIdentity,
    FileObjectState,
    FilesystemPolicyError,
    FilesystemSymlinkError,
)
from src.platform_pki.persisted_identity import (
    IdentitySentinel,
    PersistedIdentityError,
    format_gnu_stat_timestamp,
    parse_directory_identity,
    parse_file_identity,
    parse_file_object_state,
    parse_gnu_stat_timestamp,
    serialize_directory_identity,
    serialize_file_identity,
    serialize_file_object_state,
    serialize_identity_sentinel,
)


ROOT = Path(__file__).resolve().parents[1]
ORACLE_ROOT = ROOT / "tests/pki/oracles/platform-pki-ca-rollover"
ORACLE_COMMIT = "ba9dd57214cae18f82c83dfb54b6ddce13882280"
ORACLE_HASHES = {
    "platform-pki-ca-rollover": "7e9430e6d17969d5d1779e8073b9757e08157625e16b91969991e611953b806b",
    "platform-pki-root-create": "44f12eae381eedfb6414b6135ebc2bd8ff5fa2a99731adbc80c4a3201b107a3b",
    "platform-pki-intermediate-create": "efd59fff7a0913f048f1799ce6d91caa751e477fc1c29884f868a95b37fbcdf7",
    "lib/platform-pki-common.sh": "dee644be8ab6236cb368a553493f55b53a90c3aead291550f7e635c080a5494f",
}


def _values(
    fields: tuple[str, ...],
    operation: RecoveryOperation,
) -> dict[str, str]:
    values = {field: f"value-{index}" for index, field in enumerate(fields)}
    values.update(
        schema=str(
            {
                RecoveryOperation.LEGACY_MIGRATE: 2,
                RecoveryOperation.ROOT_BOOTSTRAP: 3,
                RecoveryOperation.INTERMEDIATE_BOOTSTRAP: 3,
            }[operation]
        ),
        operation=operation.value,
        committed="false",
        transaction={
            RecoveryOperation.LEGACY_MIGRATE: "migrate-20260809-120000-1",
            RecoveryOperation.ROOT_BOOTSTRAP: "root-bootstrap-20260809-120000-2",
            RecoveryOperation.INTERMEDIATE_BOOTSTRAP: "intermediate-bootstrap-20260809-120000-3",
        }[operation],
    )
    if "recovery_action" in fields:
        values["recovery_action"] = "none"
        values["recovery_step"] = "none"
    if "root_mutated" in fields:
        values["root_mutated"] = "false"
    return values


def _payload(fields: tuple[str, ...], values: dict[str, str]) -> bytes:
    return b"".join(f"{field}={values[field]}\n".encode("ascii") for field in fields)


def _valid_payload(
    fields: tuple[str, ...],
    operation: RecoveryOperation,
) -> bytes:
    return _payload(fields, _values(fields, operation))


def test_frozen_ca_recovery_oracles_match_provenance_and_modes() -> None:
    plan = (ROOT / "docs/plans/platform-pki-python-migration.md").read_text(
        encoding="utf-8"
    )
    assert ORACLE_COMMIT in plan
    assert {
        path.relative_to(ORACLE_ROOT).as_posix()
        for path in ORACLE_ROOT.rglob("*")
    } == {
        "lib",
        "lib/platform-pki-common.sh",
        "platform-pki-ca-rollover",
        "platform-pki-root-create",
        "platform-pki-intermediate-create",
    }
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


def test_gnu_timestamp_parser_and_formatter_preserve_nanoseconds_and_offset() -> None:
    text = "2026-08-09 20:43:21.226255893 +0200"
    value = parse_gnu_stat_timestamp(text)
    assert value == 1_786_301_001_226_255_893
    assert format_gnu_stat_timestamp(value, utc_offset_minutes=120) == text
    assert format_gnu_stat_timestamp(-1, utc_offset_minutes=0) == (
        "1969-12-31 23:59:59.999999999 +0000"
    )
    negative_offset = "1969-12-31 18:29:59.999999999 -0530"
    assert parse_gnu_stat_timestamp(negative_offset) == -1
    assert format_gnu_stat_timestamp(-1, utc_offset_minutes=-330) == negative_offset


@pytest.mark.parametrize(
    "value",
    (
        "2026-02-29 00:00:00.000000000 +0000",
        "2024-13-01 00:00:00.000000000 +0000",
        "2024-01-00 00:00:00.000000000 +0000",
        "2024-01-01 24:00:00.000000000 +0000",
        "2024-01-01 00:60:00.000000000 +0000",
        "2024-01-01 00:00:60.000000000 +0000",
        "2024-01-01 00:00:00.00000000 +0000",
        "2024-01-01T00:00:00.000000000 +0000",
        "2024-01-01 00:00:00.000000000 -0000",
        "2024-01-01 00:00:00.000000000 +2400",
        "2024-01-01 00:00:00.000000000 +0060",
        "2024-01-01 00:00:00.000000000 +0000\n",
    ),
)
def test_gnu_timestamp_rejects_noncanonical_or_impossible_values(value: str) -> None:
    with pytest.raises(PersistedIdentityError):
        parse_gnu_stat_timestamp(value)


def test_full_file_identity_round_trips_exact_gnu_stat_shape() -> None:
    mtime = parse_gnu_stat_timestamp("2026-08-09 20:43:21.226255893 +0200")
    ctime = parse_gnu_stat_timestamp("2026-08-09 20:43:22.000000001 +0200")
    identity = FileIdentity(2049, 42, 1000, 0o600, 1, 9, mtime, ctime, "regular")
    encoded = serialize_file_identity(identity, utc_offset_minutes=120)
    assert encoded == (
        "2049:42:1000:600:1:9:2026-08-09 20:43:21.226255893 +0200:"
        "2026-08-09 20:43:22.000000001 +0200:regular file"
    )
    assert parse_file_identity(encoded) == identity


def test_empty_file_object_state_uses_exact_gnu_type_and_directory_is_distinct() -> None:
    empty = FileObjectState(1, 2, 3, 0o600, 1, 0, "regular")
    directory = DirectoryIdentity(1, 4, 3, 0o700, "directory")
    assert serialize_file_object_state(empty) == "1:2:3:600:1:0:regular empty file"
    assert parse_file_object_state(serialize_file_object_state(empty)) == empty
    assert serialize_directory_identity(directory) == "1:4:3:700:directory"
    assert parse_directory_identity(serialize_directory_identity(directory)) == directory
    with pytest.raises(PersistedIdentityError):
        parse_directory_identity("1:2:3:600:1:0:regular empty file")


@pytest.mark.parametrize(
    "parser,value",
    (
        (parse_file_object_state, "01:2:3:600:1:1:regular file"),
        (parse_file_object_state, "1:0:3:600:1:1:regular file"),
        (parse_file_object_state, "1:2:4294967296:600:1:1:regular file"),
        (parse_file_object_state, "1:2:3:0600:1:1:regular file"),
        (parse_file_object_state, "1:2:3:10000:1:1:regular file"),
        (parse_file_object_state, "1:2:3:600:0:1:regular file"),
        (parse_file_object_state, "1:2:3:600:1:9223372036854775808:regular file"),
        (parse_file_object_state, "1:2:3:600:1:0:regular file"),
        (parse_file_object_state, "1:2:3:600:1:1:regular empty file"),
        (parse_file_object_state, "1:2:3:600:1:1:socket"),
        (parse_file_object_state, "1:2:3:600:1:1:regular file\x7f"),
        (parse_directory_identity, "1:2:3:0700:directory"),
        (parse_directory_identity, "18446744073709551616:2:3:700:directory"),
    ),
)
def test_identity_codecs_reject_noncanonical_overflow_and_wrong_types(
    parser, value: str
) -> None:
    with pytest.raises(PersistedIdentityError):
        parser(value)


def test_identity_sentinels_are_accepted_only_when_explicitly_allowed() -> None:
    for value, sentinel in (
        ("absent", IdentitySentinel.ABSENT),
        ("none", IdentitySentinel.NONE),
    ):
        with pytest.raises(PersistedIdentityError):
            parse_file_identity(value)
        assert parse_file_identity(
            value, allowed_sentinels=frozenset((sentinel,))
        ) is sentinel
        assert serialize_identity_sentinel(
            sentinel, allowed_sentinels=frozenset((sentinel,))
        ) == value
        with pytest.raises(PersistedIdentityError):
            parse_file_identity(
                value,
                allowed_sentinels=frozenset(
                    ({IdentitySentinel.NONE, IdentitySentinel.ABSENT} - {sentinel})
                ),
            )
        with pytest.raises(PersistedIdentityError):
            serialize_identity_sentinel(
                sentinel,
                allowed_sentinels=frozenset(
                    ({IdentitySentinel.NONE, IdentitySentinel.ABSENT} - {sentinel})
                ),
            )


@pytest.mark.parametrize(
    ("operation", "writer_fields", "recovery_fields", "count"),
    (
        (
            RecoveryOperation.ROOT_BOOTSTRAP,
            recovery.ROOT_BOOTSTRAP_WRITER_FIELDS,
            recovery.ROOT_BOOTSTRAP_RECOVERY_FIELDS,
            20,
        ),
        (
            RecoveryOperation.INTERMEDIATE_BOOTSTRAP,
            recovery.INTERMEDIATE_BOOTSTRAP_WRITER_FIELDS,
            recovery.INTERMEDIATE_BOOTSTRAP_RECOVERY_FIELDS,
            56,
        ),
        (
            RecoveryOperation.LEGACY_MIGRATE,
            recovery.LEGACY_MIGRATION_WRITER_FIELDS,
            recovery.LEGACY_MIGRATION_RECOVERY_FIELDS,
            56,
        ),
    ),
)
def test_final_bash_writer_and_c_locale_orders_are_both_accepted(
    operation: RecoveryOperation,
    writer_fields: tuple[str, ...],
    recovery_fields: tuple[str, ...],
    count: int,
) -> None:
    writer = parse_recovery_record(_valid_payload(writer_fields, operation))
    rewritten = parse_recovery_record(_valid_payload(recovery_fields, operation))
    assert len(writer_fields) == len(recovery_fields) == count
    assert writer.operation is rewritten.operation is operation
    assert writer.order is RecoveryRecordOrder.WRITER
    assert rewritten.order is RecoveryRecordOrder.C_LOCALE
    assert writer.to_recovery_bytes() == _payload(
        recovery_fields, dict(writer.items())
    )


def test_legacy_58_field_recovery_checkpoint_is_typed_and_sorted() -> None:
    fields = recovery.LEGACY_MIGRATION_CHECKPOINT_FIELDS
    values = _values(fields, RecoveryOperation.LEGACY_MIGRATE)
    values["recovery_action"] = "resume"
    values["recovery_step"] = "resume-root-rename-pending"
    record = parse_recovery_record(_payload(fields, values))
    assert len(fields) == 58
    assert record.recovery_action is RecoveryAction.RESUME
    assert record.order is RecoveryRecordOrder.C_LOCALE
    assert record.to_recovery_bytes() == _payload(fields, values)
    assert serialize_recovery_rewrite(values) == _payload(fields, values)


@pytest.mark.parametrize(
    "mutation,diagnostic",
    (
        (lambda lines: [*lines, lines[0]], "duplicate"),
        (lambda lines: [*lines, b"unknown=value"], "unexpected"),
        (lambda lines: lines[1:], "missing"),
        (lambda lines: [lines[0].split(b"=", 1)[0] + b"=", *lines[1:]], "empty"),
        (lambda lines: [lines[0].replace(b"=", b"\x01=", 1), *lines[1:]], "invalid field"),
        (lambda lines: [lines[0] + b"\x7f", *lines[1:]], "non-canonical"),
    ),
)
def test_typed_parser_rejects_duplicate_unknown_missing_empty_and_control_fields(
    mutation, diagnostic: str
) -> None:
    payload = _valid_payload(
        recovery.ROOT_BOOTSTRAP_WRITER_FIELDS,
        RecoveryOperation.ROOT_BOOTSTRAP,
    )
    changed = b"\n".join(mutation(payload.rstrip(b"\n").split(b"\n"))) + b"\n"
    with pytest.raises(RecoveryRecordError, match=diagnostic):
        parse_recovery_record(changed)


@pytest.mark.parametrize("ending", (b"", b"\n\n"))
def test_recovery_record_requires_exactly_one_final_newline(ending: bytes) -> None:
    payload = _valid_payload(
        recovery.ROOT_BOOTSTRAP_WRITER_FIELDS,
        RecoveryOperation.ROOT_BOOTSTRAP,
    ).rstrip(b"\n")
    with pytest.raises(RecoveryRecordError, match="exactly one newline"):
        parse_recovery_record(payload + ending)


def test_typed_parser_rejects_noncanonical_order_schema_operation_and_values() -> None:
    fields = recovery.ROOT_BOOTSTRAP_WRITER_FIELDS
    values = _values(fields, RecoveryOperation.ROOT_BOOTSTRAP)
    invalid_cases = []
    invalid_cases.append(_payload((fields[1], fields[0], *fields[2:]), values))
    for field, value in (
        ("schema", "03"),
        ("schema", "2147483648"),
        ("operation", "intermediate-bootstrap"),
        ("transaction", "root-bootstrap-invalid"),
        ("committed", "yes"),
        ("recovery_action", "resume"),
        ("recovery_step", "unexpected-without-action"),
    ):
        changed = dict(values)
        changed[field] = value
        invalid_cases.append(_payload(fields, changed))
    for payload in invalid_cases:
        with pytest.raises(RecoveryRecordError):
            parse_recovery_record(payload)


def test_intermediate_root_mutated_is_boolean() -> None:
    fields = recovery.INTERMEDIATE_BOOTSTRAP_WRITER_FIELDS
    values = _values(fields, RecoveryOperation.INTERMEDIATE_BOOTSTRAP)
    values["root_mutated"] = "yes"
    with pytest.raises(RecoveryRecordError, match="root_mutated"):
        parse_recovery_record(_payload(fields, values))


def test_operation_specific_action_enum_rejects_root_resume() -> None:
    assert parse_recovery_action(
        RecoveryOperation.INTERMEDIATE_BOOTSTRAP, "resume"
    ) is RecoveryAction.RESUME
    with pytest.raises(RecoveryRecordError, match="invalid for the operation"):
        parse_recovery_action(RecoveryOperation.ROOT_BOOTSTRAP, "resume")


def test_schema5_generic_parser_is_strict_but_does_not_claim_typed_semantics() -> None:
    fields = ("operation", "schema", "transaction")
    values = {
        "operation": "rollover-prepare",
        "schema": "5",
        "transaction": "prepare-root-20260809-120000-4",
    }
    record = parse_rollover_prepare_structure(_payload(fields, values))
    assert isinstance(record, GenericRecoveryRecord)
    assert record.fields == fields
    with pytest.raises(RecoveryRecordError, match="typed semantic validation"):
        parse_recovery_record(_payload(fields, values))
    with pytest.raises(RecoveryRecordError, match="C-locale"):
        parse_rollover_prepare_structure(
            _payload(("schema", "operation", "transaction"), values)
        )


def test_schema5_runtime_key_expansion_is_recorded_without_false_fixed_shape() -> None:
    assert len(recovery.ROLLOVER_PREPARE_DECLARED_FIELDS) == 206
    assert len(recovery.ROLLOVER_PREPARE_RUNTIME_IDENTITY_FIELDS) == 13
    assert len(
        set(recovery.ROLLOVER_PREPARE_DECLARED_FIELDS)
        | set(recovery.ROLLOVER_PREPARE_RUNTIME_IDENTITY_FIELDS)
    ) == 219
    assert "root_stage_cert_identity" in recovery.ROLLOVER_PREPARE_RUNTIME_IDENTITY_FIELDS
    assert "root_stage_index_identity" in recovery.ROLLOVER_PREPARE_RUNTIME_IDENTITY_FIELDS
    assert len(
        set(recovery.ROLLOVER_PREPARE_DECLARED_FIELDS)
        | {"root_stage_cert_identity", "root_stage_index_identity"}
    ) == 208


@pytest.mark.parametrize(
    ("loader", "payload"),
    (
        (
            load_recovery_record,
            _valid_payload(
                recovery.ROOT_BOOTSTRAP_WRITER_FIELDS,
                RecoveryOperation.ROOT_BOOTSTRAP,
            ),
        ),
        (
            load_rollover_prepare_structure,
            _payload(
                ("operation", "schema", "transaction"),
                {
                    "operation": "rollover-prepare",
                    "schema": "5",
                    "transaction": "prepare-root-20260809-120000-4",
                },
            ),
        ),
    ),
    ids=("schema-2-3", "schema-5"),
)
def test_identity_open_loaders_enforce_mode_owner_link_count_and_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    loader,
    payload: bytes,
) -> None:
    path = tmp_path / "journal"
    path.write_bytes(payload)
    path.chmod(0o600)
    loader(path, max_bytes=len(payload))
    with pytest.raises(FilesystemPolicyError):
        loader(path, max_bytes=len(payload) - 1)

    path.chmod(0o644)
    with pytest.raises(FilesystemPolicyError):
        loader(path)
    path.chmod(0o600)
    linked = tmp_path / "linked"
    os.link(path, linked)
    with pytest.raises(FilesystemPolicyError):
        loader(path)
    linked.unlink()

    current_uid = os.geteuid()
    monkeypatch.setattr(recovery.os, "geteuid", lambda: current_uid + 1)
    with pytest.raises(FilesystemPolicyError):
        loader(path)


@pytest.mark.parametrize(
    ("loader", "payload"),
    (
        (
            load_recovery_record,
            _valid_payload(
                recovery.ROOT_BOOTSTRAP_WRITER_FIELDS,
                RecoveryOperation.ROOT_BOOTSTRAP,
            ),
        ),
        (
            load_rollover_prepare_structure,
            _payload(
                ("operation", "schema", "transaction"),
                {
                    "operation": "rollover-prepare",
                    "schema": "5",
                    "transaction": "prepare-root-20260809-120000-4",
                },
            ),
        ),
    ),
    ids=("schema-2-3", "schema-5"),
)
def test_identity_open_loaders_reject_symlink(
    tmp_path: Path, loader, payload: bytes
) -> None:
    journal = tmp_path / "journal"
    journal.write_bytes(payload)
    journal.chmod(0o600)
    link = tmp_path / "link"
    link.symlink_to(journal)
    with pytest.raises(FilesystemSymlinkError):
        loader(link)
