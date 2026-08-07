import re
from dataclasses import dataclass


class InventoryError(ValueError):
    """The inventory does not satisfy the supported byte grammar."""


@dataclass(frozen=True, slots=True)
class InventoryEntry:
    field: str
    value: str


@dataclass(frozen=True, slots=True)
class InventoryService:
    name: str
    entries: tuple[InventoryEntry, ...]
    common_name: str
    dns: tuple[str, ...]
    ips: tuple[str, ...]
    days: str | None
    key_custody: str
    target: str | None
    validation_boundary_sha256: str | None
    rollback_hold_seconds: str | None


@dataclass(frozen=True, slots=True)
class Inventory:
    services: tuple[InventoryService, ...]

    @property
    def canonical_bytes(self) -> bytes:
        rows = (
            f"{service.name}\t{entry.field}\t{entry.value}\n"
            for service in self.services
            for entry in service.entries
        )
        return "".join(rows).encode("ascii")


@dataclass(slots=True)
class _ServiceBuilder:
    name: bytes
    entries: list[tuple[bytes, bytes]]
    fields: dict[bytes, list[bytes]]


_SERVICE = re.compile(rb"  ([A-Za-z0-9][A-Za-z0-9_.-]*):")
_SCALAR = re.compile(
    rb"    (common_name|days|key_custody|target|"
    rb"validation_boundary_sha256|rollback_hold_seconds): +(.+)"
)
_LIST = re.compile(rb"    (dns|ips):")
_LIST_ITEM = re.compile(rb"      - +(.+)")
_DNS_NAME = re.compile(
    rb"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    rb"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*"
)
_TARGET = re.compile(rb"[a-z0-9][a-z0-9.-]*")
_SHA256 = re.compile(rb"[0-9a-f]{64}")
_POSITIVE_DECIMAL = re.compile(rb"[1-9][0-9]*")
_DIGITS = re.compile(rb"[0-9]+")
_HOST_LOCAL_FIELDS = (
    b"target",
    b"validation_boundary_sha256",
    b"rollback_hold_seconds",
)


def _text(value: bytes) -> str:
    return value.decode("ascii")


def _safe_value(value: bytes) -> str | None:
    if all(0x20 <= byte <= 0x7E for byte in value):
        return value.decode("ascii")
    return None


def _value_error(message: str, value: bytes) -> InventoryError:
    safe_value = _safe_value(value)
    if safe_value is not None:
        message = f"{message}: {safe_value}"
    return InventoryError(message)


def _parse_value(value: bytes) -> bytes:
    if not value:
        raise InventoryError("Inventory value must be non-empty")
    if value[:1] in (b"'", b'"'):
        quote = value[:1]
        if len(value) < 2 or value[-1:] != quote:
            raise InventoryError("Inventory value has unmatched quotes")
        value = value[1:-1]
        if quote in value:
            raise InventoryError(
                "Inventory value contains an unsupported embedded quote"
            )
    elif b"'" in value or b'"' in value:
        raise InventoryError("Inventory value contains an unsupported quote")
    if b"\\" in value:
        raise InventoryError("Inventory value contains unsupported backslash syntax")
    if b"#" in value:
        raise InventoryError("Inventory inline comments are not supported")
    return value


def _validate_openssl_value(label: str, value: bytes) -> None:
    if not value:
        raise InventoryError(f"{label} must be non-empty")
    if b"$" in value:
        raise InventoryError(
            f"{label} must not contain OpenSSL variable expansion syntax"
        )
    if value[:1] == b" " or value[-1:] == b" ":
        raise InventoryError(f"{label} must not start or end with whitespace")


def _validate_dns(label: str, value: bytes) -> None:
    _validate_openssl_value(label, value)
    if len(value) > 253:
        raise InventoryError(f"{label} must be at most 253 characters")
    if _DNS_NAME.fullmatch(value) is None:
        raise InventoryError(
            f"{label} must be a DNS name using letters, digits, dots, and hyphens"
        )


def _validate_ip(label: str, value: bytes) -> None:
    _validate_openssl_value(label, value)
    octets = value.split(b".")
    if (
        len(octets) != 4
        or any(
            not 1 <= len(octet) <= 3
            or _DIGITS.fullmatch(octet) is None
            or int(octet) > 255
            for octet in octets
        )
    ):
        raise InventoryError(f"{label} must be a valid IPv4 address")


def _validate_days(value: bytes) -> None:
    if _DIGITS.fullmatch(value) is None:
        raise _value_error("Days value must be numeric", value)
    normalized = value.lstrip(b"0") or b"0"
    if len(normalized) > 6 or (
        len(normalized) == 6 and normalized > b"365000"
    ):
        raise _value_error("Days value must be at most 365000", value)
    if normalized == b"0":
        raise _value_error("Days value must be at least 1", value)


def _validate_scalar(service: bytes, field: bytes, value: bytes) -> None:
    service_text = _text(service)
    if field == b"common_name":
        _validate_dns(f"common_name for service {service_text}", value)
    elif field == b"days":
        _validate_days(value)
    elif field == b"key_custody":
        if value != b"host-local":
            raise InventoryError(
                f"Inventory key_custody for service {service_text} must be host-local"
            )
    elif field == b"target":
        if _TARGET.fullmatch(value) is None:
            raise InventoryError(
                f"Inventory target for service {service_text} is invalid"
            )
    elif field == b"validation_boundary_sha256":
        if _SHA256.fullmatch(value) is None:
            raise InventoryError(
                "Inventory validation_boundary_sha256 for service "
                f"{service_text} must be 64 lowercase hexadecimal characters"
            )
    elif _POSITIVE_DECIMAL.fullmatch(value) is None:
        raise InventoryError(
            "Inventory rollback_hold_seconds for service "
            f"{service_text} must be a canonical positive decimal"
        )


def _finish_list(service: _ServiceBuilder | None, field: bytes | None) -> None:
    if service is not None and field in (b"dns", b"ips") and not service.fields[field]:
        raise InventoryError(
            f"Inventory {_text(field)} list for service {_text(service.name)} "
            "must not be empty"
        )


def _build_service(builder: _ServiceBuilder) -> InventoryService:
    name = _text(builder.name)
    fields = builder.fields
    if b"common_name" not in fields:
        raise InventoryError(f"common_name is missing for service: {name}")
    if b"dns" not in fields and b"ips" not in fields:
        raise InventoryError(
            f"Service must define at least one DNS or IP SAN: {name}"
        )

    host_local = b"key_custody" in fields
    for field in _HOST_LOCAL_FIELDS:
        if host_local and field not in fields:
            raise InventoryError(
                f"Inventory {_text(field)} is required for host-local service: {name}"
            )
        if not host_local and field in fields:
            raise InventoryError(
                f"Inventory {_text(field)} is allowed only for key_custody: "
                f"host-local service: {name}"
            )

    def scalar(field: bytes) -> str | None:
        values = fields.get(field)
        return _text(values[0]) if values is not None else None

    return InventoryService(
        name=name,
        entries=tuple(
            InventoryEntry(field=_text(field), value=_text(value))
            for field, value in builder.entries
        ),
        common_name=_text(fields[b"common_name"][0]),
        dns=tuple(_text(value) for value in fields.get(b"dns", ())),
        ips=tuple(_text(value) for value in fields.get(b"ips", ())),
        days=scalar(b"days"),
        key_custody="host-local" if host_local else "managed",
        target=scalar(b"target"),
        validation_boundary_sha256=scalar(b"validation_boundary_sha256"),
        rollback_hold_seconds=scalar(b"rollback_hold_seconds"),
    )


def parse_inventory(data: bytes) -> Inventory:
    """Parse the strict inventory byte language and return an immutable model."""

    if not isinstance(data, bytes):
        raise InventoryError("Inventory input must be bytes")
    if b"\0" in data:
        raise InventoryError("Inventory NUL bytes are not supported")

    lines = data.split(b"\n")
    if data.endswith(b"\n"):
        lines.pop()

    saw_document = False
    saw_services = False
    builders: list[_ServiceBuilder] = []
    services_seen: set[bytes] = set()
    service: _ServiceBuilder | None = None
    field: bytes | None = None

    for line_number, line in enumerate(lines, 1):
        if b"\t" in line:
            raise InventoryError(
                f"Inventory tabs are not supported at line {line_number}"
            )
        if any(byte < 0x20 or byte == 0x7F for byte in line):
            raise InventoryError(
                f"Inventory control characters are not supported at line {line_number}"
            )
        if not line.strip(b" ") or line.lstrip(b" ").startswith(b"#"):
            continue
        if line == b"---":
            if saw_document or saw_services:
                raise InventoryError(
                    f"Inventory document marker is misplaced at line {line_number}"
                )
            saw_document = True
            continue
        if line == b"...":
            raise InventoryError(
                f"Inventory document end markers are not supported at line {line_number}"
            )
        if line == b"services:":
            if saw_services:
                raise InventoryError(
                    f"Inventory contains duplicate services at line {line_number}"
                )
            saw_services = True
            continue
        if not saw_services:
            raise InventoryError(
                f"Inventory content outside services at line {line_number}"
            )

        match = _SERVICE.fullmatch(line)
        if match is not None:
            _finish_list(service, field)
            name = match.group(1)
            if name in services_seen:
                raise InventoryError(
                    f"Inventory contains duplicate service: {_text(name)}"
                )
            services_seen.add(name)
            service = _ServiceBuilder(name=name, entries=[], fields={})
            builders.append(service)
            field = None
            continue
        if service is None:
            raise InventoryError(
                f"Inventory requires a service key at line {line_number}"
            )

        match = _SCALAR.fullmatch(line)
        if match is not None:
            _finish_list(service, field)
            matched_field = match.group(1)
            if matched_field in service.fields:
                raise InventoryError(
                    f"Inventory contains duplicate {_text(matched_field)} field for service "
                    f"{_text(service.name)}"
                )
            value = _parse_value(match.group(2))
            _validate_scalar(service.name, matched_field, value)
            service.fields[matched_field] = [value]
            service.entries.append((matched_field, value))
            field = matched_field
            continue

        match = _LIST.fullmatch(line)
        if match is not None:
            _finish_list(service, field)
            matched_field = match.group(1)
            if matched_field in service.fields:
                raise InventoryError(
                    f"Inventory contains duplicate {_text(matched_field)} field for service "
                    f"{_text(service.name)}"
                )
            service.fields[matched_field] = []
            field = matched_field
            continue

        match = _LIST_ITEM.fullmatch(line)
        if match is not None:
            if field not in (b"dns", b"ips"):
                raise InventoryError(
                    "Inventory list item has no dns or ips field at line "
                    f"{line_number}"
                )
            value = _parse_value(match.group(1))
            values = service.fields[field]
            if value in values:
                raise InventoryError(
                    f"Inventory contains duplicate {_text(field)} SAN for service "
                    f"{_text(service.name)}: {_safe_value(value) or '<invalid value>'}"
                )
            if field == b"dns":
                _validate_dns(f"DNS SAN for service {_text(service.name)}", value)
            else:
                _validate_ip(f"IP SAN for service {_text(service.name)}", value)
            values.append(value)
            service.entries.append((field, value))
            continue
        raise InventoryError(f"Unsupported inventory grammar at line {line_number}")

    if not saw_services:
        raise InventoryError("Inventory must contain exactly one services mapping")
    if not builders:
        raise InventoryError("Inventory must define at least one service")
    _finish_list(service, field)

    return Inventory(services=tuple(_build_service(builder) for builder in builders))
