from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from src.platform_pki.records import (
    OrderedRecord,
    RecordError,
    RecordSpec,
    parse_ordered_record,
    serialize_ordered_record,
)


SPEC = RecordSpec(("schema", "service", "digest"), schema="1")
CANONICAL = b"schema=1\nservice=api\ndigest=sha256=abc123\n"


def test_parse_returns_immutable_mapping_and_round_trips_exactly() -> None:
    record = parse_ordered_record(CANONICAL, SPEC)

    assert isinstance(record, OrderedRecord)
    assert tuple(record) == SPEC.fields
    assert record.pairs == (
        ("schema", "1"),
        ("service", "api"),
        ("digest", "sha256=abc123"),
    )
    assert record["service"] == "api"
    assert record.to_bytes() == CANONICAL
    assert SPEC.parse(CANONICAL) == record


@pytest.mark.parametrize(
    ("data", "message"),
    (
        (b"service=api\nschema=1\ndigest=x\n", "canonical order"),
        (b"schema=1\nservice=api\n", "missing"),
        (b"schema=1\nservice=api\ndigest=x\nextra=y\n", "unexpected"),
        (b"schema=1\nservice=api\nservice=again\n", "duplicate"),
    ),
)
def test_parse_rejects_reordered_missing_extra_and_duplicate_fields(
    data: bytes,
    message: str,
) -> None:
    with pytest.raises(RecordError, match=message):
        parse_ordered_record(data, SPEC)


@pytest.mark.parametrize(
    "data",
    (
        b"Schema=1\nservice=api\ndigest=x\n",
        b"schema=1\nservice-name=api\ndigest=x\n",
        b"schema=1\n=api\ndigest=x\n",
    ),
)
def test_parse_rejects_noncanonical_keys(data: bytes) -> None:
    with pytest.raises(RecordError, match="invalid field key"):
        parse_ordered_record(data, SPEC)


@pytest.mark.parametrize("invalid", (b"\x00", b"\t", b"\r", b"\x7f", b"\x80"))
def test_parse_rejects_controls_del_and_non_ascii(invalid: bytes) -> None:
    with pytest.raises(RecordError, match="non-canonical value"):
        parse_ordered_record(b"schema=1\nservice=api" + invalid + b"\ndigest=x\n", SPEC)


def test_empty_value_policy_is_explicit() -> None:
    data = b"schema=1\nservice=\ndigest=x\n"

    with pytest.raises(RecordError, match="empty value"):
        parse_ordered_record(data, SPEC)

    permissive = RecordSpec(SPEC.fields, allow_empty=True, schema="1")
    assert parse_ordered_record(data, permissive)["service"] == ""
    assert serialize_ordered_record({"schema": "1", "service": "", "digest": "x"}, permissive) == data


def test_values_split_only_at_the_first_equals() -> None:
    record = parse_ordered_record(CANONICAL, SPEC)
    assert record["digest"] == "sha256=abc123"


def test_exact_schema_is_optional_but_enforced_when_configured() -> None:
    with pytest.raises(RecordError, match="schema"):
        parse_ordered_record(CANONICAL.replace(b"schema=1", b"schema=2"), SPEC)
    assert parse_ordered_record(
        CANONICAL.replace(b"schema=1", b"schema=2"),
        RecordSpec(SPEC.fields),
    )["schema"] == "2"


@pytest.mark.parametrize(
    "data",
    (
        CANONICAL.removesuffix(b"\n"),
        CANONICAL + b"\n",
        CANONICAL + b"\n\n\n",
        CANONICAL.replace(b"service=api\n", b"service=api\n\n"),
        CANONICAL.replace(b"service=api\n", b"service=api\r\n"),
    ),
)
def test_parse_requires_exactly_one_final_newline(data: bytes) -> None:
    with pytest.raises(RecordError):
        parse_ordered_record(data, SPEC)


def test_serializer_uses_spec_order_for_reverse_ordered_mapping() -> None:
    reverse = {"digest": "sha256=abc123", "service": "api", "schema": "1"}
    assert tuple(reverse) == tuple(reversed(SPEC.fields))
    assert serialize_ordered_record(reverse, SPEC) == CANONICAL
    assert SPEC.serialize(reverse) == CANONICAL


def test_serializer_canonicalizes_ordered_pairs() -> None:
    pairs = (("digest", "sha256=abc123"), ("schema", "1"), ("service", "api"))
    assert serialize_ordered_record(pairs, SPEC) == CANONICAL


@pytest.mark.parametrize(
    ("values", "message"),
    (
        ((("schema", "1"), ("service", "api"), ("service", "again")), "duplicate"),
        ({"schema": "1", "service": "api", "digest": "x", "extra": "y"}, "unexpected"),
        ({"schema": "1", "service": "api"}, "missing"),
        ({"schema": "2", "service": "api", "digest": "x"}, "schema"),
        ({"schema": "1", "service": "api\nsecret", "digest": "x"}, "non-canonical"),
        ({"schema": "1", "service": "caf\N{LATIN SMALL LETTER E WITH ACUTE}", "digest": "x"}, "non-canonical"),
        ({"schema": "1", "service": "", "digest": "x"}, "empty"),
    ),
)
def test_serializer_rejects_invalid_mappings_and_pairs(values: object, message: str) -> None:
    with pytest.raises(RecordError, match=message):
        serialize_ordered_record(values, SPEC)  # type: ignore[arg-type]


def test_errors_do_not_disclose_source_keys_or_values() -> None:
    secret = "DO_NOT_DISCLOSE"
    with pytest.raises(RecordError) as parse_error:
        parse_ordered_record(f"schema=1\nsecret_key={secret}\ndigest=x\n".encode(), SPEC)
    with pytest.raises(RecordError) as serialize_error:
        serialize_ordered_record(
            {"schema": "1", "service": secret, "digest": "bad\x00value"},
            SPEC,
        )

    assert secret not in str(parse_error.value)
    assert secret not in str(serialize_error.value)
    assert "secret_key" not in str(parse_error.value)


def test_specs_and_records_are_deeply_immutable() -> None:
    source_fields = ["schema", "service", "digest"]
    spec = RecordSpec(source_fields, schema="1")  # type: ignore[arg-type]
    source_fields[1] = "changed"
    record = parse_ordered_record(CANONICAL, spec)

    assert spec.fields == SPEC.fields
    with pytest.raises(FrozenInstanceError):
        spec.schema = "2"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        record._pairs = ()  # type: ignore[misc]
    with pytest.raises(TypeError):
        record["service"] = "changed"  # type: ignore[index]
