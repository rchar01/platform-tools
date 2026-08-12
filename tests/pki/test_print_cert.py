from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
from collections.abc import Callable, Iterator, Mapping, Sequence
from pathlib import Path

import pytest

from ..harness import ProcessResult
from .migration_harness import run_differential_case


ROOT = Path(__file__).resolve().parents[2]
PTY_CAPTURE = ROOT / "tests/cli/pty-capture.py"
TOOL = ROOT / "bin/platform-pki-print-cert"
ORACLE = ROOT / "tests/pki/oracles/platform-pki-print-cert/platform-pki-print-cert"
ORACLE_COMMIT = "4cd6b2294760571ffed632295de441c34a4c0eb1"
ORACLE_SHA256 = "544b14fd0a006d96feb9bd9383cf57bdb6bb6ea4c3312b0324220c5ebcb07e92"
UNIFIED = ROOT / "bin/platform-pki"
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
if [[ $1 == verify && ${OPENSSL_FAIL_VERIFY:-} == 1 ]]; then
  printf '%s\\n' 'active issuer verify failed' >&2
  exit 7
fi
if [[ $1 == verify && ${OPENSSL_VERIFY_STDERR:-} == 1 ]]; then
  printf '%s\\n' 'active issuer verify warning' >&2
fi
if [[ $1 == x509 && $* != *'-ext '* && ${OPENSSL_FAIL_DETAILS:-} == 1 ]]; then
  printf '%s\\n' 'partial certificate details'
  printf '%s\\n' 'certificate detail read failed' >&2
  exit 7
fi
case $* in
  *'-ext subjectAltName') printf '%s\\n' 'X509v3 Subject Alternative Name:' '    DNS:platform.example.internal' ;;
  *'-ext extendedKeyUsage') printf '%s\\n' 'X509v3 Extended Key Usage:' '    TLS Web Server Authentication' ;;
  *'-ext keyUsage')
    if [[ ${OPENSSL_MISSING_EXTENSION:-} == keyUsage ]]; then
      printf '%s\\n' 'No extensions in certificate' >&2
      exit 1
    fi
    printf '%s\\n' 'X509v3 Key Usage:' '    Digital Signature'
    ;;
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
    tool: Path | Sequence[str | Path] = TOOL,
) -> ProcessResult:
    command = (tool,) if isinstance(tool, Path) else tuple(tool)
    effective_environment = environment
    if command == (ORACLE,):
        effective_environment = dict(os.environ if environment is None else environment)
        effective_environment["PLATFORM_TOOLS_LIB_DIR"] = os.fspath(
            ROOT / "tests/pki/oracles/final-bash-source/lib"
        )
    return process_runner([*command, *arguments], env=effective_environment)


OPERATIONAL_TOOLS = (
    pytest.param((ORACLE,), id="bash-oracle"),
    pytest.param((TOOL,), id="python-compatibility"),
    pytest.param((UNIFIED, "print-cert"), id="python-unified"),
)


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


def test_frozen_oracle_matches_recorded_provenance() -> None:
    digest = hashlib.sha256(ORACLE.read_bytes()).hexdigest()
    plan = (ROOT / "docs/plans/platform-pki-python-migration.md").read_text(
        encoding="utf-8"
    )

    assert digest == ORACLE_SHA256
    assert ORACLE_COMMIT in plan


def test_tty_help_color_and_no_color(
    process_runner: Callable[..., ProcessResult],
) -> None:
    colored = process_runner(["python3", PTY_CAPTURE, TOOL, "--help"])
    uncolored = process_runner(
        ["python3", PTY_CAPTURE, TOOL, "--help"],
        env={**os.environ, "NO_COLOR": "1"},
    )

    assert colored.status == 0
    assert "\x1b" in colored.stdout
    assert colored.stderr == ""
    assert uncolored.status == 0
    assert "\x1b" not in uncolored.stdout
    assert uncolored.stderr == ""


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


@pytest.mark.parametrize("tool", OPERATIONAL_TOOLS)
def test_missing_inventory_does_not_invoke_openssl(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    tool: tuple[Path | str, ...],
) -> None:
    environment, log = _fake_environment(tmp_path, "missing-inventory-openssl.log")
    pki = tmp_path / "missing-inventory"
    pki.mkdir(mode=0o700)

    result = _run(
        process_runner, ["platform-example", "--pki-dir", pki], environment, tool
    )

    assert result.status == 1
    assert result.stdout == ""
    assert "Service inventory is missing or unreadable:" in result.stderr
    assert not log.exists()


@pytest.mark.parametrize("tool", OPERATIONAL_TOOLS)
def test_unknown_service(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    tool: tuple[Path | str, ...],
) -> None:
    pki = _pki_tree(tmp_path)
    environment, _ = _fake_environment(tmp_path, "unknown-service-openssl.log")

    result = _run(
        process_runner, ["unknown-service", "--pki-dir", pki], environment, tool
    )

    assert result.status == 1
    assert result.stdout == ""
    assert "Service is not defined in" in result.stderr


@pytest.mark.parametrize("tool", OPERATIONAL_TOOLS)
def test_missing_certificate(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    tool: tuple[Path | str, ...],
) -> None:
    pki = _pki_tree(tmp_path, certificate=False)
    environment, _ = _fake_environment(tmp_path, "missing-cert-openssl.log")

    result = _run(
        process_runner, ["--pki-dir", pki, "platform-example"], environment, tool
    )

    assert result.status == 1
    assert result.stdout == ""
    assert "Required file is missing:" in result.stderr


@pytest.mark.parametrize("tool", OPERATIONAL_TOOLS)
def test_prints_certificate_details_in_command_order(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    tool: tuple[Path | str, ...],
) -> None:
    pki = _pki_tree(tmp_path)
    environment, log = _fake_environment(tmp_path, "openssl.log")

    result = _run(
        process_runner, ["--pki-dir", pki, "platform-example"], environment, tool
    )

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


@pytest.mark.parametrize("tool", OPERATIONAL_TOOLS)
def test_missing_optional_extension_preserves_openssl_diagnostic(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    tool: tuple[Path | str, ...],
) -> None:
    pki = _pki_tree(tmp_path)
    environment, _ = _fake_environment(tmp_path, "missing-extension-openssl.log")
    environment = dict(environment, OPENSSL_MISSING_EXTENSION="keyUsage")

    result = _run(
        process_runner, ["--pki-dir", pki, "platform-example"], environment, tool
    )

    assert result.status == 0
    assert result.stdout.startswith("Service: platform-example\nsubject=")
    assert "X509v3 Key Usage:" not in result.stdout
    assert result.stdout.endswith("    TLS Web Server Authentication\n")
    assert result.stderr == "No extensions in certificate\n"


@pytest.mark.parametrize("tool", OPERATIONAL_TOOLS)
def test_active_issuer_failure_precedes_service_output(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    tool: tuple[Path | str, ...],
) -> None:
    pki = _pki_tree(tmp_path)
    environment, _ = _fake_environment(tmp_path, "failed-issuer-openssl.log")
    environment = dict(environment, OPENSSL_FAIL_VERIFY="1")

    result = _run(
        process_runner, ["--pki-dir", pki, "platform-example"], environment, tool
    )

    assert result.status == 1
    assert result.stdout == ""
    assert result.stderr == (
        "active issuer verify failed\n"
        "[ERROR] Active intermediate does not verify against its recorded root\n"
    )


@pytest.mark.parametrize("tool", OPERATIONAL_TOOLS)
def test_successful_active_issuer_stderr_is_preserved(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    tool: tuple[Path | str, ...],
) -> None:
    pki = _pki_tree(tmp_path)
    environment, _ = _fake_environment(tmp_path, "issuer-warning-openssl.log")
    environment = dict(environment, OPENSSL_VERIFY_STDERR="1")

    result = _run(
        process_runner, ["--pki-dir", pki, "platform-example"], environment, tool
    )

    assert result.status == 0
    assert result.stdout.startswith("Service: platform-example\nsubject=")
    assert result.stderr == "active issuer verify warning\n"


@pytest.mark.parametrize("tool", OPERATIONAL_TOOLS)
def test_required_detail_failure_preserves_child_status_and_output(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    tool: tuple[Path | str, ...],
) -> None:
    pki = _pki_tree(tmp_path)
    environment, log = _fake_environment(tmp_path, "failed-details-openssl.log")
    environment = dict(environment, OPENSSL_FAIL_DETAILS="1")

    result = _run(
        process_runner, ["--pki-dir", pki, "platform-example"], environment, tool
    )

    assert result.status == 7
    assert result.stdout == "Service: platform-example\npartial certificate details\n"
    assert result.stderr == "certificate detail read failed\n"
    assert len(log.read_text(encoding="utf-8").splitlines()) == 2


def test_bash_python_success_state_and_output_are_equivalent(tmp_path: Path) -> None:
    seed = tmp_path / "seed"
    seed.mkdir(mode=0o700)
    _pki_tree(seed)
    environment, _ = _fake_environment(tmp_path, "differential-openssl.log")
    environment = dict(
        environment,
        PLATFORM_TOOLS_LIB_DIR=os.fspath(
            ROOT / "tests/pki/oracles/final-bash-source/lib"
        ),
    )

    result = run_differential_case(
        seed,
        tmp_path / "case",
        Path("pki"),
        lambda root: (
            ORACLE,
            "--pki-dir",
            root / "pki",
            "platform-example",
        ),
        lambda root: (
            UNIFIED,
            "print-cert",
            "--pki-dir",
            root / "pki",
            "platform-example",
        ),
        environment,
        run_options={"timeout": 30},
    )

    result.assert_equivalent()


def _normalize_case_root(root: Path, output: str) -> str:
    return output.replace(os.fspath(root), "<CASE>")


@pytest.mark.parametrize(
    ("relative", "content"),
    (
        pytest.param(
            "state/csr/finalization-recovery-journal",
            "operation=csr-finalize\n",
            id="finalization",
        ),
        pytest.param(
            "state/csr/recovery-journal",
            "operation=csr-sign\n",
            id="signing",
        ),
        pytest.param(
            "state/rollover/recovery-required",
            "recovery required\n",
            id="rollover-marker",
        ),
        pytest.param(
            "state/rollover/journal",
            "operation=rollover-prepare\ncommitted=false\n",
            id="rollover-journal",
        ),
        pytest.param(
            "state/csr/finalization-recovery-journal",
            "invalid record\n",
            id="malformed-finalization",
        ),
        pytest.param(
            "state/rollover/journal",
            "operation=other\rcommitted=true\r",
            id="control-delimited-rollover-journal",
        ),
    ),
)
def test_bash_python_recovery_gates_are_equivalent(
    tmp_path: Path, relative: str, content: str
) -> None:
    seed = tmp_path / "seed"
    seed.mkdir(mode=0o700)
    pki = _pki_tree(seed)
    _write(pki / relative, content)
    environment, _ = _fake_environment(tmp_path, "recovery-gate-openssl.log")
    environment = dict(
        environment,
        PLATFORM_TOOLS_LIB_DIR=os.fspath(
            ROOT / "tests/pki/oracles/final-bash-source/lib"
        ),
    )

    result = run_differential_case(
        seed,
        tmp_path / "case",
        Path("pki"),
        lambda root: (
            ORACLE,
            "--pki-dir",
            root / "pki",
            "platform-example",
        ),
        lambda root: (
            UNIFIED,
            "print-cert",
            "--pki-dir",
            root / "pki",
            "platform-example",
        ),
        environment,
        output_normalizers=(_normalize_case_root,),
        run_options={"timeout": 30},
    )

    result.assert_equivalent()


def test_explicit_library_directory_is_ignored(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
    pki = _pki_tree(tmp_path)
    environment, _ = _fake_environment(tmp_path, "explicit-openssl.log")
    copied_tool = tmp_path / "explicit/bin/platform-pki-print-cert"
    copied_tool.parent.mkdir(mode=0o700, parents=True)
    shutil.copy2(TOOL, copied_tool)
    environment = dict(
        environment, PLATFORM_TOOLS_LIB_DIR=os.fspath(tmp_path / "explicit/missing")
    )

    result = _run(
        process_runner,
        ["platform-example", f"--pki-dir={pki}"],
        environment,
        copied_tool,
    )

    assert result.status == 0
    assert result.stderr == ""


def test_missing_installed_share_library_is_ignored(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
    pki = _pki_tree(tmp_path)
    environment, _ = _fake_environment(tmp_path, "installed-openssl.log")
    copied_tool = tmp_path / "installed/bin/platform-pki-print-cert"
    copied_tool.parent.mkdir(mode=0o700, parents=True)
    shutil.copy2(TOOL, copied_tool)
    environment = dict(
        environment, PLATFORM_TOOLS_SHARE_DIR=os.fspath(tmp_path / "installed/share")
    )

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


def test_command_operates_without_shared_library(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
    pki = _pki_tree(tmp_path)
    tool, isolated = _isolated_tool(tmp_path)
    environment, _ = _fake_environment(tmp_path, "isolated-openssl.log")
    environment = {
        **environment,
        "HOME": isolated["HOME"],
        "PLATFORM_TOOLS_SHARE_DIR": isolated["PLATFORM_TOOLS_SHARE_DIR"],
    }

    result = _run(process_runner, ["platform-example", "--pki-dir", pki], environment, tool)

    assert result.status == 0, result.stderr
    assert result.stdout
    assert result.stderr == ""
