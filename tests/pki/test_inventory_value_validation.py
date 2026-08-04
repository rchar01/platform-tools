from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
COMMON = ROOT / "lib/platform-pki-common.sh"
INVENTORY_VALIDATOR = (
    'source "$1"; '
    'pki_validate_service_inventory_values platform-example "$2" "$3" "$4"'
)
DAYS_VALIDATOR = 'source "$1"; pki_validate_days "$2"'
ENV_EXPANSION = "$ENV::AWS_SECRET_ACCESS_KEY"


def _write_values(path: Path, values: tuple[str, ...]) -> None:
    path.write_text("".join(f"{value}\n" for value in values), encoding="utf-8")


@pytest.mark.parametrize(
    ("common_name", "dns", "ips", "status", "message"),
    [
        ("app.example.internal", ("app.example.internal", "app"), ("192.0.2.10",), 0, ""),
        (ENV_EXPANSION, ("app.example.internal",), ("192.0.2.10",), 1, "common_name for service platform-example must not contain OpenSSL variable expansion syntax"),
        ("app.example.internal", (ENV_EXPANSION,), ("192.0.2.10",), 1, "DNS SAN for service platform-example must not contain OpenSSL variable expansion syntax"),
        ("app.example.internal", ("app.example.internal",), (ENV_EXPANSION,), 1, "IP SAN for service platform-example must not contain OpenSSL variable expansion syntax"),
        ("app.example.internal", ("bad name.example",), ("192.0.2.10",), 1, "DNS SAN for service platform-example must be a DNS name using letters, digits, dots, and hyphens"),
        ("app.example.internal", ("app.example.internal",), ("999.0.2.10",), 1, "IP SAN for service platform-example must be a valid IPv4 address"),
        ("app.example.internal", ("app.example.internal",), ("1:2:3:4:5:6:7:8:9",), 1, "IP SAN for service platform-example must be a valid IPv4 address"),
        ("app.example.internal", ("app.example.internal",), ("2001:db8::1",), 1, "IP SAN for service platform-example must be a valid IPv4 address"),
        ("app.example.internal", ("*.example.internal",), ("192.0.2.10",), 1, "DNS SAN for service platform-example must be a DNS name using letters, digits, dots, and hyphens"),
        (" app.example.internal", ("app.example.internal",), ("192.0.2.10",), 1, "common_name for service platform-example must not start or end with whitespace"),
        ("app.example.internal", ("app.example.internal",), ("192.0.2.10\t",), 1, "IP SAN for service platform-example must not contain control characters"),
    ],
    ids=["valid", "common-name-expansion", "dns-expansion", "ip-expansion", "bad-dns", "bad-ipv4", "bad-ipv6", "ipv6-unsupported", "wildcard-dns", "common-name-whitespace", "ip-control"],
)
def test_service_inventory_values(
    tmp_path: Path,
    process_runner,
    common_name: str,
    dns: tuple[str, ...],
    ips: tuple[str, ...],
    status: int,
    message: str,
) -> None:
    dns_file = tmp_path / "dns"
    ips_file = tmp_path / "ips"
    _write_values(dns_file, dns)
    _write_values(ips_file, ips)

    result = process_runner(
        ["bash", "-c", INVENTORY_VALIDATOR, "_", COMMON, common_name, dns_file, ips_file]
    )

    assert result.status == status
    assert result.stdout == ""
    assert result.stderr == ("" if status == 0 else f"[ERROR] {message}\n")


@pytest.mark.parametrize(
    ("value", "status", "message"),
    [
        ("18446744073709551617", 1, "Days value must be at most 365000"),
        ("365001", 1, "Days value must be at most 365000"),
        ("000001", 0, ""),
    ],
    ids=["overflow", "above-maximum", "leading-zero-valid"],
)
def test_days_validation(
    process_runner, value: str, status: int, message: str
) -> None:
    result = process_runner(["bash", "-c", DAYS_VALIDATOR, "_", COMMON, value])

    assert result.status == status
    assert result.stdout == ""
    assert result.stderr == ("" if status == 0 else f"[ERROR] {message}: {value}\n")
