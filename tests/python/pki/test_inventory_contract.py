from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[3]
COMMON = ROOT / "lib/platform-pki-common.sh"
VALIDATOR = 'source "$1"; pki_validate_inventory_file "$2" "$3"'
VALID_INVENTORY = b"""---
# order is intentionally non-canonical
services:
  api-1:
    ips:
      - '192.0.2.10'
    days: 1
    common_name: "api.example.internal"
  dns_only:
    common_name: dns.example.internal
    dns:
      - dns.example.internal
"""


def _validate(tmp_path: Path, process_runner, content: bytes):
    inventory = tmp_path / "inventory.yml"
    canonical = tmp_path / "canonical"
    inventory.write_bytes(content)
    return process_runner(
        ["bash", "-c", VALIDATOR, "_", COMMON, inventory, canonical]
    ), canonical


def test_valid_inventory_writes_canonical_snapshot(
    tmp_path: Path, process_runner
) -> None:
    result, canonical = _validate(tmp_path, process_runner, VALID_INVENTORY)

    assert (result.status, result.stdout, result.stderr) == (0, "", "")
    rows = canonical.read_text(encoding="utf-8").splitlines()
    assert "api-1\tcommon_name\tapi.example.internal" in rows
    assert "dns_only\tdns\tdns.example.internal" in rows


@pytest.mark.parametrize(
    "consumer",
    [
        "platform-pki-service-issue",
        "platform-pki-service-renew",
        "platform-pki-service-verify",
        "platform-pki-list-expiry",
        "platform-pki-print-cert",
        "platform-pki-export-ansible",
    ],
)
def test_consumer_loads_exactly_one_inventory_snapshot(consumer: str) -> None:
    source = ROOT / "bashly" / consumer / "src/root_command.sh"
    assert source.read_text(encoding="utf-8").count("pki_load_inventory_snapshot") == 1


@pytest.mark.parametrize(
    ("content", "error"),
    [
        (b"services:\n", "Inventory must define at least one service"),
        (b"services:\n  api:\n    common_name: api.example\n    dns:\n      - api.example\n  api:\n    common_name: api.example\n    dns:\n      - api.example\n", "Inventory contains duplicate service: api"),
        (b"services:\n  api:\n    common_name: api.example\n    common_name: other.example\n    dns:\n      - api.example\n", "Inventory contains duplicate common_name field for service api"),
        (b"services:\n  api:\n    common_name: api.example\n    dns:\n      - api.example\n      - api.example\n", "Inventory contains duplicate dns SAN for service api: api.example"),
        (b"services:\n  api:\n    common_name: api.example\n    dns:\n      - api.example\n    deploy: host\n", "Unsupported inventory grammar at line 6"),
        (b"services:\n api:\n    common_name: api.example\n    dns:\n      - api.example\n", "Inventory requires a service key at line 2"),
        (b"services:\n  api:\n\tcommon_name: api.example\n", "Inventory tabs are not supported at line 3"),
        (b"services:\n  api:\n    common_name: api.example # no\n    dns:\n      - api.example\n", "Inventory inline comments are not supported\n[ERROR] common_name for service api must be non-empty"),
        (b"services:\n  api:\n    common_name: api.example\n    dns:\n", "Inventory dns list for service api must not be empty"),
        (b"services:\n  api:\n    common_name: api.example\n", "Service must define at least one DNS or IP SAN: api"),
        (b"services:\n  api:\n    common_name: api.example\n    ips:\n      - 999.0.2.1\n", "IP SAN for service api must be a valid IPv4 address"),
        (b"---\n---\nservices:\n  api:\n    common_name: api.example\n    dns:\n      - api.example\n", "Inventory document marker is misplaced at line 2"),
        (b"services:\n  api:\n    common_name: api.example\n    dns:\n      - api.example\nother:\n", "Unsupported inventory grammar at line 6"),
    ],
    ids=["no-services", "duplicate-service", "duplicate-field", "duplicate-san", "unknown-field", "bad-indent", "tab", "inline-comment", "empty-list", "no-san", "bad-ip", "duplicate-document", "trailing"],
)
def test_invalid_inventory_is_rejected(
    tmp_path: Path, process_runner, content: bytes, error: str
) -> None:
    result, _canonical = _validate(tmp_path, process_runner, content)

    assert result.status == 1
    assert result.stdout == ""
    assert result.stderr == f"[ERROR] {error}\n"


@pytest.mark.parametrize(
    "content",
    [
        b"serv\0ices:\n",
        b"services:\n  api:\n    common_name: api\0.example\n    dns:\n      - api.example\n",
        b"services:\n  api:\n    common_name: api.example\n    dns:\n      - api\0.example\n",
        b"# comment\0hidden\nservices:\n  api:\n    common_name: api.example\n    dns:\n      - api.example\n",
        b"services:\0\n  api:\n    common_name: api.example\n    dns:\n      - api.example\n",
    ],
    ids=["key", "scalar", "list", "comment", "structure"],
)
def test_inventory_rejects_nul_at_every_grammar_location(
    tmp_path: Path, process_runner, content: bytes
) -> None:
    result, canonical = _validate(tmp_path, process_runner, content)

    assert result.status == 1
    assert result.stdout == ""
    assert result.stderr == "[ERROR] Inventory NUL bytes are not supported\n"
    assert not canonical.exists()
