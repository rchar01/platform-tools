"""Strict parsing and serialization for ordered ``key=value`` records."""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from typing import Any


_KEY_PATTERN = re.compile(r"[a-z0-9_]+", re.ASCII)


class RecordError(ValueError):
    """A record does not have the required canonical structure."""


@dataclass(frozen=True, slots=True)
class RecordSpec:
    """The ordered fields and value policy for one record type."""

    fields: tuple[str, ...]
    allow_empty: bool = False
    schema: str | None = None

    def __post_init__(self) -> None:
        if isinstance(self.fields, (str, bytes)):
            raise ValueError("record fields must be a sequence of keys")
        try:
            fields = tuple(self.fields)
        except TypeError:
            raise ValueError("record fields must be a sequence of keys") from None
        if not fields:
            raise ValueError("record specification must contain at least one field")
        if any(not isinstance(field, str) or not _KEY_PATTERN.fullmatch(field) for field in fields):
            raise ValueError("record specification contains an invalid field key")
        if len(set(fields)) != len(fields):
            raise ValueError("record specification contains duplicate field keys")
        if type(self.allow_empty) is not bool:
            raise ValueError("record empty-value policy must be boolean")
        if self.schema is not None:
            if "schema" not in fields:
                raise ValueError("record specification schema requires a schema field")
            _validate_value(self.schema, allow_empty=self.allow_empty, specification=True)
        object.__setattr__(self, "fields", fields)

    def parse(self, data: bytes) -> OrderedRecord:
        return parse_ordered_record(data, self)

    def serialize(
        self,
        values: Mapping[str, str] | Iterable[tuple[str, str]] | OrderedRecord,
    ) -> bytes:
        return serialize_ordered_record(values, self)


@dataclass(frozen=True, slots=True)
class OrderedRecord(Mapping[str, str]):
    """An immutable record retaining its canonical field order."""

    spec: RecordSpec
    _pairs: tuple[tuple[str, str], ...]

    def __post_init__(self) -> None:
        if not isinstance(self.spec, RecordSpec):
            raise TypeError("record spec must be a RecordSpec")
        pairs = _validated_pairs(self._pairs, self.spec)
        object.__setattr__(self, "_pairs", pairs)

    def __getitem__(self, key: str) -> str:
        for field, value in self._pairs:
            if field == key:
                return value
        raise KeyError(key)

    def __iter__(self) -> Iterator[str]:
        return (field for field, _value in self._pairs)

    def __len__(self) -> int:
        return len(self._pairs)

    @property
    def pairs(self) -> tuple[tuple[str, str], ...]:
        return self._pairs

    def to_bytes(self) -> bytes:
        return serialize_ordered_record(self, self.spec)


def _validate_value(value: Any, *, allow_empty: bool, specification: bool = False) -> None:
    error_type = ValueError if specification else RecordError
    if not isinstance(value, str):
        raise error_type("record value must be text")
    if not value and not allow_empty:
        raise error_type("record contains an empty value")
    if any(ord(character) < 0x20 or ord(character) > 0x7E for character in value):
        raise error_type("record contains a non-canonical value")


def _input_pairs(
    values: Mapping[str, str] | Iterable[tuple[str, str]] | OrderedRecord,
) -> tuple[tuple[Any, Any], ...]:
    if isinstance(values, OrderedRecord):
        return values.pairs
    if isinstance(values, Mapping):
        source: Iterable[Any] = values.items()
    elif isinstance(values, (str, bytes, bytearray)):
        raise RecordError("record values must be a mapping or ordered pairs")
    else:
        source = values

    try:
        entries = tuple(source)
    except Exception:
        raise RecordError("record values could not be read") from None

    pairs: list[tuple[Any, Any]] = []
    for entry in entries:
        if isinstance(entry, (str, bytes, bytearray)):
            raise RecordError("record contains a malformed field pair")
        try:
            key, value = entry
        except (TypeError, ValueError):
            raise RecordError("record contains a malformed field pair") from None
        pairs.append((key, value))
    return tuple(pairs)


def _validated_pairs(
    values: Mapping[str, str] | Iterable[tuple[str, str]] | OrderedRecord,
    spec: RecordSpec,
) -> tuple[tuple[str, str], ...]:
    pairs = _input_pairs(values)
    by_key: dict[str, str] = {}
    for key, value in pairs:
        if not isinstance(key, str) or not _KEY_PATTERN.fullmatch(key):
            raise RecordError("record contains an invalid field key")
        if key in by_key:
            raise RecordError("record contains a duplicate field")
        _validate_value(value, allow_empty=spec.allow_empty)
        by_key[key] = value

    expected = set(spec.fields)
    actual = set(by_key)
    if actual - expected:
        raise RecordError("record contains an unexpected field")
    if expected - actual:
        raise RecordError("record is missing a required field")
    if spec.schema is not None and by_key["schema"] != spec.schema:
        raise RecordError("record schema does not match specification")
    return tuple((field, by_key[field]) for field in spec.fields)


def parse_ordered_record(data: bytes, spec: RecordSpec) -> OrderedRecord:
    """Parse canonical record bytes according to *spec*."""

    if not isinstance(spec, RecordSpec):
        raise TypeError("record spec must be a RecordSpec")
    if not isinstance(data, bytes):
        raise TypeError("record input must be bytes")
    if not data.endswith(b"\n") or data.endswith(b"\n\n"):
        raise RecordError("record must end with exactly one newline")

    lines = data[:-1].split(b"\n")
    if len(lines) < len(spec.fields):
        raise RecordError("record is missing a required field")
    if len(lines) > len(spec.fields):
        raise RecordError("record contains an unexpected field")

    pairs: list[tuple[str, str]] = []
    seen: set[bytes] = set()
    for line in lines:
        if b"=" not in line:
            raise RecordError("record contains a malformed field")
        raw_key, raw_value = line.split(b"=", 1)
        if not re.fullmatch(rb"[a-z0-9_]+", raw_key):
            raise RecordError("record contains an invalid field key")
        if raw_key in seen:
            raise RecordError("record contains a duplicate field")
        seen.add(raw_key)
        if not raw_value and not spec.allow_empty:
            raise RecordError("record contains an empty value")
        if any(byte < 0x20 or byte > 0x7E for byte in raw_value):
            raise RecordError("record contains a non-canonical value")
        pairs.append((raw_key.decode("ascii"), raw_value.decode("ascii")))

    keys = tuple(key for key, _value in pairs)
    expected = set(spec.fields)
    actual = set(keys)
    if actual - expected:
        raise RecordError("record contains an unexpected field")
    if expected - actual:
        raise RecordError("record is missing a required field")
    if keys != spec.fields:
        raise RecordError("record fields are not in canonical order")
    if spec.schema is not None and dict(pairs)["schema"] != spec.schema:
        raise RecordError("record schema does not match specification")
    return OrderedRecord(spec, tuple(pairs))


def serialize_ordered_record(
    values: Mapping[str, str] | Iterable[tuple[str, str]] | OrderedRecord,
    spec: RecordSpec,
) -> bytes:
    """Validate *values* and serialize them in the order declared by *spec*."""

    if not isinstance(spec, RecordSpec):
        raise TypeError("record spec must be a RecordSpec")
    pairs = _validated_pairs(values, spec)
    return b"".join(f"{key}={value}\n".encode("ascii") for key, value in pairs)
