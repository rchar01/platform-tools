from __future__ import annotations

import os
import shutil
import tempfile
from collections.abc import Callable, Iterator, Mapping, Sequence
from pathlib import Path

import pytest

from ..harness import ProcessResult


ROOT = Path(__file__).resolve().parents[3]
TOOL = ROOT / "bin/platform-pki-service-verify"
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
INVENTORY = """services:
  platform-example:
    common_name: platform.example.internal
    dns:
      - platform.example.internal
    ips:
      - 192.0.2.10
"""
FAKE_COMMON = """# shellcheck source=../../../../lib/platform-pki-common.sh
source "$REAL_COMMON"

pki_key_matches_cert() { printf '%s\\n' key >>"$VERIFY_LOG"; [[ ${VERIFY_FAILURE:-} != key ]]; }
pki_cert_has_ca_false() { printf '%s\\n' ca >>"$VERIFY_LOG"; [[ ${VERIFY_FAILURE:-} != ca ]]; }
pki_cert_has_server_auth() { printf '%s\\n' eku >>"$VERIFY_LOG"; [[ ${VERIFY_FAILURE:-} != eku ]]; }
pki_cert_has_dns_san() { printf '%s\\n' dns >>"$VERIFY_LOG"; [[ ${VERIFY_FAILURE:-} != dns ]]; }
pki_cert_has_ip_san() { printf '%s\\n' ip >>"$VERIFY_LOG"; [[ ${VERIFY_FAILURE:-} != ip ]]; }
"""
FAKE_OPENSSL = """#!/usr/bin/env bash
set -euo pipefail
case $1 in
  verify)
    printf '%s\\n' trust >>"$VERIFY_LOG"
    if [[ ${VERIFY_FAILURE:-} == trust ]]; then
      printf '%s\\n' 'certificate chain verification failed' >&2
      exit 1
    fi
    ;;
  x509)
    printf '%s\\n' lifetime >>"$VERIFY_LOG"
    [[ ${VERIFY_FAILURE:-} != lifetime ]] || exit 1
    ;;
esac
"""


@pytest.fixture
def tmp_path() -> Iterator[Path]:
    temporary_root = ROOT / ".tmp"
    temporary_root.mkdir(mode=0o700, exist_ok=True)
    path = Path(tempfile.mkdtemp(prefix="pytest-service-verify.", dir=temporary_root))
    path.chmod(0o700)
    yield path
    shutil.rmtree(path)


def _write(path: Path, content: str, mode: int = 0o600) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    path.chmod(mode)


def _workspace(tmp_path: Path) -> tuple[Path, Path, Path]:
    pki = tmp_path / "pki"
    for relative in (
        "inventory",
        "services/platform-example/private",
        "services/platform-example/certs",
        "authorities/roots/g1/certs",
        "authorities/intermediates/g1-i1/certs",
        "locks",
        "state/rollover",
    ):
        (pki / relative).mkdir(mode=0o700, parents=True, exist_ok=True)
    for directory in (pki, *(path for path in pki.rglob("*") if path.is_dir())):
        directory.chmod(0o700)
    _write(pki / "inventory/services.yml", INVENTORY)
    for relative in (
        "services/platform-example/private/tls.key",
        "services/platform-example/certs/tls.crt",
        "authorities/roots/g1/certs/root-ca.crt",
        "authorities/intermediates/g1-i1/certs/intermediate-ca.crt",
    ):
        _write(pki / relative, "", 0o644)
    _write(pki / "state/active-issuer", "root=g1\nintermediate=g1-i1\n")
    _write(
        pki / "services/platform-example/issuer",
        "root=g1\nintermediate=g1-i1\n",
    )
    fake_library = tmp_path / "fake-lib/platform-pki-common.sh"
    fake_openssl = tmp_path / "fake-bin/openssl"
    _write(fake_library, FAKE_COMMON, 0o644)
    _write(fake_openssl, FAKE_OPENSSL, 0o755)
    return pki, fake_library, fake_openssl.parent


def _environment(
    tmp_path: Path, fake_library: Path, fake_bin: Path, failure: str
) -> tuple[Mapping[str, str], Path]:
    log = tmp_path / f"verify-{failure}.log"
    environment = dict(os.environ)
    environment.update(
        PATH=f"{fake_bin}:{environment['PATH']}",
        REAL_COMMON=os.fspath(ROOT / "lib/platform-pki-common.sh"),
        PLATFORM_TOOLS_LIB_DIR=os.fspath(fake_library.parent),
        VERIFY_FAILURE=failure,
        VERIFY_LOG=os.fspath(log),
    )
    return environment, log


def _run(
    process_runner: Callable[..., ProcessResult],
    arguments: Sequence[str | Path],
    environment: Mapping[str, str] | None = None,
    tool: Path = TOOL,
) -> ProcessResult:
    return process_runner([tool, *arguments], env=environment)


def test_help(process_runner: Callable[..., ProcessResult]) -> None:
    result = _run(process_runner, ["--help"])
    assert result.status == 0
    assert "Usage:" in result.stdout
    assert "platform-pki-service-verify --version | -v" in result.stdout
    assert result.stderr == ""


def test_version(process_runner: Callable[..., ProcessResult]) -> None:
    result = _run(process_runner, ["--version"])
    assert result == ProcessResult(
        result.args, 0, f"platform-pki-service-verify {VERSION}\n", ""
    )


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        pytest.param(["--unknown"], "invalid option: --unknown", id="unknown-option"),
        pytest.param([], "missing required argument: SERVICE", id="missing-service"),
        pytest.param(
            ["platform-example", "--min-days", "nope"],
            "Days value must be numeric: nope",
            id="nonnumeric-min-days",
        ),
    ],
)
def test_argument_errors(
    process_runner: Callable[..., ProcessResult], arguments: list[str], message: str
) -> None:
    result = _run(process_runner, arguments)
    assert result.status == 1
    assert result.stdout == ""
    assert message in result.stderr


def test_invalid_service_name(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
    pki, _, _ = _workspace(tmp_path)
    result = _run(process_runner, ["bad/name", "--pki-dir", pki])
    assert result.status == 1
    assert result.stdout == ""
    assert "Invalid service name: bad/name" in result.stderr


def test_successful_verification_order(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
    pki, fake_library, fake_bin = _workspace(tmp_path)
    environment, log = _environment(tmp_path, fake_library, fake_bin, "none")

    result = _run(
        process_runner,
        ["platform-example", "--pki-dir", pki, "--min-days", "30"],
        environment,
    )

    assert result == ProcessResult(
        result.args, 0, "[OK] Verified service certificate: platform-example\n", ""
    )
    assert log.read_text(encoding="utf-8") == (
        "trust\ntrust\nkey\nca\neku\ndns\nip\nlifetime\n"
    )


@pytest.mark.parametrize(
    ("failure", "message", "order"),
    [
        pytest.param(
            "trust", "certificate chain verification failed", "trust\n", id="trust"
        ),
        pytest.param(
            "key", "Private key does not match certificate", "trust\ntrust\nkey\n", id="key"
        ),
        pytest.param(
            "ca", "Certificate is missing CA:false", "trust\ntrust\nkey\nca\n", id="ca"
        ),
        pytest.param(
            "eku", "Certificate is missing serverAuth EKU",
            "trust\ntrust\nkey\nca\neku\n", id="eku"
        ),
        pytest.param(
            "dns", "Certificate is missing DNS SAN 'platform.example.internal'",
            "trust\ntrust\nkey\nca\neku\ndns\n", id="dns"
        ),
        pytest.param(
            "ip", "Certificate is missing IP SAN '192.0.2.10'",
            "trust\ntrust\nkey\nca\neku\ndns\nip\n", id="ip"
        ),
        pytest.param(
            "lifetime", "Certificate has less than 30 days remaining",
            "trust\ntrust\nkey\nca\neku\ndns\nip\nlifetime\n", id="lifetime"
        ),
    ],
)
def test_verification_failure_stops_in_order(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    failure: str,
    message: str,
    order: str,
) -> None:
    pki, fake_library, fake_bin = _workspace(tmp_path)
    environment, log = _environment(tmp_path, fake_library, fake_bin, failure)

    result = _run(
        process_runner,
        ["platform-example", "--pki-dir", pki, "--min-days", "30"],
        environment,
    )

    assert result.status == 1
    assert result.stdout == ""
    assert message in result.stderr
    assert log.read_text(encoding="utf-8") == order


def test_unknown_service_stops_after_active_issuer_validation(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
    pki, fake_library, fake_bin = _workspace(tmp_path)
    environment, log = _environment(tmp_path, fake_library, fake_bin, "unknown")

    result = _run(process_runner, ["unknown-service", "--pki-dir", pki], environment)

    assert result.status == 1
    assert result.stdout == ""
    assert "Service is not defined in" in result.stderr
    assert log.read_text(encoding="utf-8") == "trust\n"


def test_installed_share_directory_layout(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
    pki, fake_library, fake_bin = _workspace(tmp_path)
    tool = tmp_path / "installed/bin/platform-pki-service-verify"
    tool.parent.mkdir(mode=0o700, parents=True)
    installed_library = tmp_path / "installed/share/lib/platform-pki-common.sh"
    installed_library.parent.mkdir(mode=0o700, parents=True)
    shutil.copy2(TOOL, tool)
    shutil.copy2(fake_library, installed_library)
    environment, _ = _environment(tmp_path, fake_library, fake_bin, "none")
    environment = dict(environment)
    environment.pop("PLATFORM_TOOLS_LIB_DIR")
    environment["PLATFORM_TOOLS_SHARE_DIR"] = os.fspath(installed_library.parents[1])

    result = _run(process_runner, ["platform-example", "--pki-dir", pki], environment, tool)

    assert result == ProcessResult(
        result.args, 0, "[OK] Verified service certificate: platform-example\n", ""
    )


def _isolated_tool(tmp_path: Path) -> tuple[Path, Mapping[str, str]]:
    tool = tmp_path / "isolated/bin/platform-pki-service-verify"
    tool.parent.mkdir(mode=0o700, parents=True)
    shutil.copy2(TOOL, tool)
    home = tmp_path / "isolated/home"
    home.mkdir(mode=0o700)
    environment = dict(
        os.environ,
        HOME=os.fspath(home),
        PLATFORM_TOOLS_SHARE_DIR=os.fspath(tmp_path / "isolated/missing"),
    )
    return tool, environment


def test_help_does_not_require_shared_library(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
    tool, environment = _isolated_tool(tmp_path)
    result = _run(process_runner, ["--help"], environment, tool)
    assert result.status == 0
    assert "Usage:" in result.stdout
    assert result.stderr == ""


def test_command_requires_shared_library(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
    pki, _, _ = _workspace(tmp_path)
    tool, environment = _isolated_tool(tmp_path)

    result = _run(process_runner, ["platform-example", "--pki-dir", pki], environment, tool)

    assert result.status == 1
    assert result.stdout == ""
    assert "platform-pki-common.sh not found" in result.stderr
