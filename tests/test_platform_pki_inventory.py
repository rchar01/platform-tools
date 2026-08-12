import os
import subprocess
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from src.platform_pki.inventory import InventoryError, parse_inventory


BOUNDARY = b"0" * 64
ROOT = Path(__file__).resolve().parents[1]


def test_valid_inventory_preserves_source_order_and_exact_canonical_bytes() -> None:
    inventory = parse_inventory(
        b"# arbitrary comment bytes are ignored: \xff\n"
        b"---\n"
        b"\n"
        b"services:\n"
        b"  edge-1:\n"
        b"    ips:\n"
        b"      - '192.000.002.010'\n"
        b"    days: 000397\n"
        b"    dns:\n"
        b'      - "edge.example.internal"\n'
        b"      - alt.example.internal\n"
        b'    common_name: "edge.example.internal"\n'
        b"  signer_2:\n"
        b"    key_custody: host-local\n"
        b"    target: host-01\n"
        b"    validation_boundary_sha256: " + BOUNDARY + b"\n"
        b"    rollback_hold_seconds: 3600\n"
        b"    common_name: signer.example.internal\n"
        b"    ips:\n"
        b"      - 203.0.113.7"
    )

    assert tuple(service.name for service in inventory.services) == (
        "edge-1",
        "signer_2",
    )
    edge, signer = inventory.services
    assert edge.common_name == "edge.example.internal"
    assert edge.dns == ("edge.example.internal", "alt.example.internal")
    assert edge.ips == ("192.000.002.010",)
    assert edge.days == "000397"
    assert edge.key_custody == "managed"
    assert edge.target is None
    assert tuple((entry.field, entry.value) for entry in edge.entries) == (
        ("ips", "192.000.002.010"),
        ("days", "000397"),
        ("dns", "edge.example.internal"),
        ("dns", "alt.example.internal"),
        ("common_name", "edge.example.internal"),
    )
    assert signer.key_custody == "host-local"
    assert signer.validation_boundary_sha256 == "0" * 64
    assert inventory.canonical_bytes == (
        b"edge-1\tips\t192.000.002.010\n"
        b"edge-1\tdays\t000397\n"
        b"edge-1\tdns\tedge.example.internal\n"
        b"edge-1\tdns\talt.example.internal\n"
        b"edge-1\tcommon_name\tedge.example.internal\n"
        b"signer_2\tkey_custody\thost-local\n"
        b"signer_2\ttarget\thost-01\n"
        b"signer_2\tvalidation_boundary_sha256\t" + BOUNDARY + b"\n"
        b"signer_2\trollback_hold_seconds\t3600\n"
        b"signer_2\tcommon_name\tsigner.example.internal\n"
        b"signer_2\tips\t203.0.113.7\n"
    )


@pytest.mark.parametrize(
    "content",
    (
        b"services:\n  api:\n    common_name: api.example\n    dns:\n      - api.example\n",
        b"# arbitrary comment byte: \xff\nservices:\n  api:\n    ips:\n      - 192.000.002.010\n    common_name: api.example\n",
        b"services:\n  api:\n    common_name:\xe2\x80\x83api.example\n    dns:\n      - api.example\n",
        b"services:\r\n  api:\r\n",
        (
            b"services:\n  signer:\n    key_custody: host-local\n"
            b"    target: signer-1\n    validation_boundary_sha256: "
            + BOUNDARY
            + b"\n    rollback_hold_seconds: 0001\n"
            b"    common_name: signer.example\n    dns:\n      - signer.example\n"
        ),
    ),
    ids=("simple", "comment-byte", "unicode-space", "crlf", "invalid-hold"),
)
def test_parser_matches_bash_c_locale_status_and_canonical_bytes(
    content: bytes, tmp_path: Path
) -> None:
    source = tmp_path / "services.yml"
    canonical = tmp_path / "canonical"
    source.write_bytes(content)
    bash = subprocess.run(
        (
            "/bin/bash",
            "--noprofile",
            "--norc",
            "-c",
            'source "$1"; pki_validate_inventory_file "$2" "$3"',
            "bash",
            os.fspath(
                ROOT
                / "tests/pki/oracles/final-bash-source/lib/platform-pki-common.sh"
            ),
            os.fspath(source),
            os.fspath(canonical),
        ),
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"LC_ALL": "C", "PATH": "/usr/local/bin:/usr/bin:/bin"},
    )
    try:
        python = parse_inventory(content)
    except InventoryError:
        assert bash.returncode != 0
    else:
        assert bash.returncode == 0, bash.stderr
        assert python.canonical_bytes == canonical.read_bytes()


def test_models_are_immutable() -> None:
    inventory = parse_inventory(
        b"services:\n"
        b"  api:\n"
        b"    common_name: api.example\n"
        b"    dns:\n"
        b"      - api.example\n"
    )

    with pytest.raises(FrozenInstanceError):
        inventory.services = ()  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        inventory.services[0].common_name = "other.example"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        inventory.services[0].entries[0].value = "other.example"  # type: ignore[misc]


@pytest.mark.parametrize(
    ("content", "message"),
    [
        (b"", "Inventory must contain exactly one services mapping"),
        (b"---\n", "Inventory must contain exactly one services mapping"),
        (b"services:\n", "Inventory must define at least one service"),
        (b"other:\n", "Inventory content outside services at line 1"),
        (b"...\n", "Inventory document end markers are not supported at line 1"),
        (b"---\n---\nservices:\n", "Inventory document marker is misplaced at line 2"),
        (b"services:\n---\n", "Inventory document marker is misplaced at line 2"),
        (b"services:\nservices:\n", "Inventory contains duplicate services at line 2"),
        (b"services: \n", "Inventory content outside services at line 1"),
        (b"services:\n api:\n", "Inventory requires a service key at line 2"),
        (b"services:\n  _api:\n", "Inventory requires a service key at line 2"),
        (b"services:\n  api: \n", "Inventory requires a service key at line 2"),
        (
            b"services:\n  api:\n    common_name: api.example\n    deploy: host\n",
            "Unsupported inventory grammar at line 4",
        ),
        (
            b"services:\n  api:\n      - api.example\n",
            "Inventory list item has no dns or ips field at line 3",
        ),
        (
            b"services:\n  api:\n    common_name: api.example\n"
            b"  api:\n    dns:\n      - api.example\n",
            "Inventory contains duplicate service: api",
        ),
        (
            b"services:\n  api:\n    common_name: api.example\n"
            b"    common_name: other.example\n",
            "Inventory contains duplicate common_name field for service api",
        ),
        (
            b"services:\n  api:\n    common_name: api.example\n"
            b"    dns:\n      - api.example\n      - api.example\n",
            "Inventory contains duplicate dns SAN for service api: api.example",
        ),
        (
            b"services:\n  api:\n    common_name: api.example\n    dns:\n",
            "Inventory dns list for service api must not be empty",
        ),
        (
            b"services:\n  api:\n    dns:\n    common_name: api.example\n",
            "Inventory dns list for service api must not be empty",
        ),
        (
            b"services:\n  api:\n    dns:\n  next:\n",
            "Inventory dns list for service api must not be empty",
        ),
        (
            b"services:\n  api:\n    dns:\n      - api.example\n",
            "common_name is missing for service: api",
        ),
        (
            b"services:\n  api:\n    common_name: api.example\n",
            "Service must define at least one DNS or IP SAN: api",
        ),
        (
            b"services:\n  api:\n    common_name: api.example\n"
            b"    dns:\n      - api.example\ntrailing:\n",
            "Unsupported inventory grammar at line 6",
        ),
    ],
    ids=(
        "empty",
        "marker-only",
        "empty-services",
        "outside-services",
        "document-end",
        "duplicate-marker",
        "late-marker",
        "duplicate-services",
        "services-trailing-space",
        "one-space-service",
        "invalid-service-start",
        "service-trailing-space",
        "unknown-field",
        "orphan-item",
        "duplicate-service",
        "duplicate-scalar",
        "duplicate-san",
        "empty-list-eof",
        "empty-list-before-field",
        "empty-list-before-service",
        "missing-common-name",
        "missing-san",
        "trailing-content",
    ),
)
def test_invalid_structure_is_rejected(content: bytes, message: str) -> None:
    with pytest.raises(InventoryError, match=f"^{re_escape(message)}$"):
        parse_inventory(content)


def re_escape(message: str) -> str:
    import re

    return re.escape(message)


@pytest.mark.parametrize(
    ("value", "message"),
    [
        (b"'api.example", "Inventory value has unmatched quotes"),
        (b'"api".example"', "Inventory value contains an unsupported embedded quote"),
        (b"api'.example", "Inventory value contains an unsupported quote"),
        (b"api\\.example", "Inventory value contains unsupported backslash syntax"),
        (b"api.example # no", "Inventory inline comments are not supported"),
        (b"''", "common_name for service api must be non-empty"),
        (
            b"'$ENV::SECRET'",
            "common_name for service api must not contain OpenSSL variable expansion syntax",
        ),
        (
            b"' api.example'",
            "common_name for service api must not start or end with whitespace",
        ),
    ],
    ids=(
        "unmatched",
        "embedded",
        "unquoted",
        "backslash",
        "inline-comment",
        "quoted-empty",
        "openssl-expansion",
        "quoted-whitespace",
    ),
)
def test_strict_scalar_value_syntax(value: bytes, message: str) -> None:
    content = (
        b"services:\n  api:\n    common_name: "
        + value
        + b"\n    dns:\n      - api.example\n"
    )
    with pytest.raises(InventoryError, match=f"^{re_escape(message)}$"):
        parse_inventory(content)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        (
            b"common_name",
            b"*.example",
            "common_name for service api must be a DNS name using letters, digits, dots, and hyphens",
        ),
        (
            b"common_name",
            b"a" * 254,
            "common_name for service api must be at most 253 characters",
        ),
        (b"days", b"one", "Days value must be numeric: one"),
        (b"days", b"0", "Days value must be at least 1: 0"),
        (b"days", b"000365001", "Days value must be at most 365000: 000365001"),
        (
            b"days",
            b"9" * 5000,
            "Days value must be at most 365000: " + "9" * 5000,
        ),
        (
            b"key_custody",
            b"managed",
            "Inventory key_custody for service api must be host-local",
        ),
        (b"target", b"HOST", "Inventory target for service api is invalid"),
        (
            b"validation_boundary_sha256",
            b"A" * 64,
            "Inventory validation_boundary_sha256 for service api must be 64 lowercase hexadecimal characters",
        ),
        (
            b"rollback_hold_seconds",
            b"01",
            "Inventory rollback_hold_seconds for service api must be a canonical positive decimal",
        ),
    ],
    ids=(
        "dns-grammar",
        "dns-length",
        "days-nonnumeric",
        "days-zero",
        "days-maximum",
        "days-unbounded-input",
        "managed-custody-is-implicit",
        "target",
        "boundary",
        "hold",
    ),
)
def test_invalid_scalar_semantics(field: bytes, value: bytes, message: str) -> None:
    content = (
        b"services:\n  api:\n    "
        + field
        + b": "
        + value
        + b"\n    common_name: api.example\n    dns:\n      - api.example\n"
    )
    with pytest.raises(InventoryError, match=f"^{re_escape(message)}$"):
        parse_inventory(content)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        (
            b"dns",
            b"bad_name.example",
            "DNS SAN for service api must be a DNS name using letters, digits, dots, and hyphens",
        ),
        (
            b"dns",
            b"$ENV::SECRET",
            "DNS SAN for service api must not contain OpenSSL variable expansion syntax",
        ),
        (b"ips", b"256.0.0.1", "IP SAN for service api must be a valid IPv4 address"),
        (b"ips", b"2001:db8::1", "IP SAN for service api must be a valid IPv4 address"),
        (b"ips", b"0000.0.0.1", "IP SAN for service api must be a valid IPv4 address"),
    ],
    ids=("dns", "dns-expansion", "ip-range", "ipv6", "ip-octet-width"),
)
def test_invalid_list_value_semantics(field: bytes, value: bytes, message: str) -> None:
    content = (
        b"services:\n  api:\n    common_name: api.example\n    "
        + field
        + b":\n      - "
        + value
        + b"\n"
    )
    with pytest.raises(InventoryError, match=f"^{re_escape(message)}$"):
        parse_inventory(content)


@pytest.mark.parametrize("missing", (b"target", b"validation_boundary_sha256", b"rollback_hold_seconds"))
def test_host_local_requires_all_deployment_fields(missing: bytes) -> None:
    values = {
        b"target": b"host-01",
        b"validation_boundary_sha256": BOUNDARY,
        b"rollback_hold_seconds": b"1",
    }
    fields = b"".join(
        b"    " + field + b": " + value + b"\n"
        for field, value in values.items()
        if field != missing
    )
    content = (
        b"services:\n  api:\n    key_custody: host-local\n"
        + fields
        + b"    common_name: api.example\n    dns:\n      - api.example\n"
    )
    with pytest.raises(
        InventoryError,
        match=(
            r"^Inventory "
            + missing.decode()
            + r" is required for host-local service: api$"
        ),
    ):
        parse_inventory(content)


@pytest.mark.parametrize("field", (b"target", b"validation_boundary_sha256", b"rollback_hold_seconds"))
def test_managed_service_rejects_host_local_deployment_fields(field: bytes) -> None:
    values = {
        b"target": b"host-01",
        b"validation_boundary_sha256": BOUNDARY,
        b"rollback_hold_seconds": b"1",
    }
    content = (
        b"services:\n  api:\n    "
        + field
        + b": "
        + values[field]
        + b"\n    common_name: api.example\n    dns:\n      - api.example\n"
    )
    with pytest.raises(
        InventoryError,
        match=(
            r"^Inventory "
            + field.decode()
            + r" is allowed only for key_custody: host-local service: api$"
        ),
    ):
        parse_inventory(content)


@pytest.mark.parametrize(
    ("bad", "message"),
    [
        (b"serv\0ices:\n", "Inventory NUL bytes are not supported"),
        (b"services:\n\t# hidden\n", "Inventory tabs are not supported at line 2"),
        (
            b"services:\r\n",
            "Inventory control characters are not supported at line 1",
        ),
        (
            b"# hidden\x0bcontrol\nservices:\n",
            "Inventory control characters are not supported at line 1",
        ),
        (
            b"services:\n# hidden\x7fcontrol\n",
            "Inventory control characters are not supported at line 2",
        ),
    ],
    ids=("nul", "tab", "cr", "vertical-tab", "delete"),
)
def test_raw_byte_controls_are_rejected_before_grammar(
    bad: bytes, message: str
) -> None:
    with pytest.raises(InventoryError, match=f"^{re_escape(message)}$"):
        parse_inventory(bad)


def test_input_must_be_bytes_and_invalid_bytes_are_not_disclosed() -> None:
    with pytest.raises(InventoryError, match="^Inventory input must be bytes$"):
        parse_inventory("services:\n")  # type: ignore[arg-type]
    with pytest.raises(
        InventoryError,
        match=(
            "^common_name for service api must be a DNS name using letters, "
            "digits, dots, and hyphens$"
        ),
    ) as error:
        parse_inventory(
            b"services:\n  api:\n    common_name: \xff\n"
            b"    dns:\n      - api.example\n"
        )
    assert "xff" not in str(error.value)
