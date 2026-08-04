from __future__ import annotations

import os
import shutil
import tempfile
from collections.abc import Callable, Iterator, Mapping, Sequence
from pathlib import Path

import pytest

from ..harness import ProcessResult


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "bin/platform-pki-print-cert"
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
INVENTORY = """services:
  platform-example:
    common_name: platform.example.internal
    dns:
      - platform.example.internal
"""
FAKE_OPENSSL = """#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$*" >>"$OPENSSL_LOG"
case $* in
  *'-ext subjectAltName') printf '%s\\n' 'X509v3 Subject Alternative Name:' '    DNS:platform.example.internal' ;;
  *'-ext extendedKeyUsage') printf '%s\\n' 'X509v3 Extended Key Usage:' '    TLS Web Server Authentication' ;;
  *'-ext keyUsage') printf '%s\\n' 'X509v3 Key Usage:' '    Digital Signature' ;;
  *) printf '%s\\n' \\
    'subject=CN=platform.example.internal' \\
    'issuer=CN=Platform Intermediate CA' \\
    'serial=1000' \\
    'notBefore=Jul 26 00:00:00 2026 GMT' \\
    'notAfter=Jul 26 00:00:00 2027 GMT' \\
    'sha256 Fingerprint=AA:BB:CC' ;;
esac
"""


@pytest.fixture
def tmp_path() -> Iterator[Path]:
    temporary_root = ROOT / ".tmp"
    temporary_root.mkdir(mode=0o700, exist_ok=True)
    path = Path(tempfile.mkdtemp(prefix="pytest-print-cert.", dir=temporary_root))
    path.chmod(0o700)
    yield path
    shutil.rmtree(path)


def _write(path: Path, content: str, mode: int = 0o600) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    path.chmod(mode)


def _pki_tree(root: Path, *, certificate: bool = True) -> Path:
    pki = root / "pki"
    for relative in (
        "inventory",
        "services/platform-example/certs",
        "authorities/roots/g1",
        "authorities/intermediates/g1-i1",
        "locks",
        "state/rollover",
    ):
        (pki / relative).mkdir(mode=0o700, parents=True, exist_ok=True)
    for directory in (pki, *(path for path in pki.rglob("*") if path.is_dir())):
        directory.chmod(0o700)
    _write(pki / "state/active-issuer", "root=g1\nintermediate=g1-i1\n")
    _write(pki / "inventory/services.yml", INVENTORY)
    if certificate:
        _write(pki / "services/platform-example/certs/tls.crt", "", 0o644)
    return pki


def _fake_environment(root: Path, log_name: str) -> tuple[Mapping[str, str], Path]:
    fake_bin = root / "fake-bin"
    _write(fake_bin / "openssl", FAKE_OPENSSL, 0o755)
    log = root / log_name
    environment = dict(os.environ)
    environment.update(
        PATH=f"{fake_bin}:{environment['PATH']}", OPENSSL_LOG=os.fspath(log)
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
    assert "platform-pki-print-cert --version | -v" in result.stdout
    assert result.stderr == ""


def test_version(process_runner: Callable[..., ProcessResult]) -> None:
    result = _run(process_runner, ["--version"])

    assert result == ProcessResult(
        result.args, 0, f"platform-pki-print-cert {VERSION}\n", ""
    )


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        pytest.param(["--unknown"], "invalid option: --unknown", id="unknown-option"),
        pytest.param([], "missing required argument: SERVICE", id="missing-service"),
        pytest.param(
            ["platform-example", "extra"], "invalid argument: extra", id="extra-argument"
        ),
    ],
)
def test_parser_errors(
    process_runner: Callable[..., ProcessResult], arguments: list[str], message: str
) -> None:
    result = _run(process_runner, arguments)

    assert result.status == 1
    assert result.stdout == ""
    assert message in result.stderr


def test_missing_inventory_does_not_invoke_openssl(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
    environment, log = _fake_environment(tmp_path, "missing-inventory-openssl.log")
    pki = tmp_path / "missing-inventory"
    pki.mkdir(mode=0o700)

    result = _run(process_runner, ["platform-example", "--pki-dir", pki], environment)

    assert result.status == 1
    assert result.stdout == ""
    assert "Service inventory is missing or unreadable:" in result.stderr
    assert not log.exists()


def test_unknown_service(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
    pki = _pki_tree(tmp_path)
    environment, _ = _fake_environment(tmp_path, "unknown-service-openssl.log")

    result = _run(process_runner, ["unknown-service", "--pki-dir", pki], environment)

    assert result.status == 1
    assert result.stdout == ""
    assert "Service is not defined in" in result.stderr


def test_missing_certificate(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
    pki = _pki_tree(tmp_path, certificate=False)
    environment, _ = _fake_environment(tmp_path, "missing-cert-openssl.log")

    result = _run(process_runner, ["--pki-dir", pki, "platform-example"], environment)

    assert result.status == 1
    assert result.stdout == ""
    assert "Required file is missing:" in result.stderr


def test_prints_certificate_details_in_command_order(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
    pki = _pki_tree(tmp_path)
    environment, log = _fake_environment(tmp_path, "openssl.log")

    result = _run(process_runner, ["--pki-dir", pki, "platform-example"], environment)

    assert result.status == 0
    assert result.stderr == ""
    assert result.stdout == (
        "Service: platform-example\n"
        "subject=CN=platform.example.internal\n"
        "issuer=CN=Platform Intermediate CA\n"
        "serial=1000\n"
        "notBefore=Jul 26 00:00:00 2026 GMT\n"
        "notAfter=Jul 26 00:00:00 2027 GMT\n"
        "sha256 Fingerprint=AA:BB:CC\n"
        "X509v3 Subject Alternative Name:\n"
        "    DNS:platform.example.internal\n"
        "X509v3 Key Usage:\n"
        "    Digital Signature\n"
        "X509v3 Extended Key Usage:\n"
        "    TLS Web Server Authentication\n"
    )
    assert len(log.read_text(encoding="utf-8").splitlines()) == 5


def test_explicit_library_directory_layout(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
    pki = _pki_tree(tmp_path)
    environment, _ = _fake_environment(tmp_path, "explicit-openssl.log")
    copied_tool = tmp_path / "explicit/bin/platform-pki-print-cert"
    copied_tool.parent.mkdir(mode=0o700, parents=True)
    library = tmp_path / "explicit/lib/platform-pki-common.sh"
    library.parent.mkdir(mode=0o700, parents=True)
    shutil.copy2(TOOL, copied_tool)
    shutil.copy2(ROOT / "lib/platform-pki-common.sh", library)
    environment = dict(environment, PLATFORM_TOOLS_LIB_DIR=os.fspath(library.parent))

    result = _run(
        process_runner,
        ["platform-example", f"--pki-dir={pki}"],
        environment,
        copied_tool,
    )

    assert result.status == 0
    assert result.stderr == ""


def test_installed_share_directory_layout(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
    pki = _pki_tree(tmp_path)
    environment, _ = _fake_environment(tmp_path, "installed-openssl.log")
    copied_tool = tmp_path / "installed/bin/platform-pki-print-cert"
    copied_tool.parent.mkdir(mode=0o700, parents=True)
    library = tmp_path / "installed/share/lib/platform-pki-common.sh"
    library.parent.mkdir(mode=0o700, parents=True)
    shutil.copy2(TOOL, copied_tool)
    shutil.copy2(ROOT / "lib/platform-pki-common.sh", library)
    environment = dict(environment, PLATFORM_TOOLS_SHARE_DIR=os.fspath(library.parents[1]))

    result = _run(
        process_runner, ["--pki-dir", pki, "platform-example"], environment, copied_tool
    )

    assert result.status == 0
    assert result.stderr == ""


def _isolated_tool(tmp_path: Path) -> tuple[Path, Mapping[str, str]]:
    copied_tool = tmp_path / "isolated/bin/platform-pki-print-cert"
    copied_tool.parent.mkdir(mode=0o700, parents=True)
    shutil.copy2(TOOL, copied_tool)
    home = tmp_path / "isolated/home"
    home.mkdir(mode=0o700)
    environment = dict(
        os.environ,
        HOME=os.fspath(home),
        PLATFORM_TOOLS_SHARE_DIR=os.fspath(tmp_path / "isolated/missing"),
    )
    return copied_tool, environment


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
    pki = _pki_tree(tmp_path)
    tool, environment = _isolated_tool(tmp_path)

    result = _run(process_runner, ["platform-example", "--pki-dir", pki], environment, tool)

    assert result.status == 1
    assert result.stdout == ""
    assert "platform-pki-common.sh not found" in result.stderr
