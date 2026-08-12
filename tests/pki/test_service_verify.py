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
TOOL = ROOT / "bin/platform-pki-service-verify"
ORACLE = ROOT / "tests/pki/oracles/platform-pki-service-verify/platform-pki-service-verify"
ORACLE_COMMIT = "b421370123db006148d0439af3e35efd47bcda2f"
ORACLE_SHA256 = "e9756ceb6df907cf4019cdb6a7f00f75ff7aab3b6c6b9588684286a5349a6cb0"
UNIFIED = ROOT / "bin/platform-pki"
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
    if [[ ${VERIFY_FAILURE:-} == trust && " $* " == *' -untrusted '* ]]; then
      printf '%s\\n' 'certificate chain verification failed' >&2
      exit 1
    fi
    ;;
  pkey)
    printf '%s\\n' key >>"$VERIFY_LOG"
    if [[ ${VERIFY_FAILURE:-} == key ]]; then
      printf '%s\\n' 'different-public-key'
    else
      printf '%s\\n' 'matching-public-key'
    fi
    ;;
  x509)
    case $* in
      *'-pubkey'*) printf '%s\\n' 'matching-public-key' ;;
      *'basicConstraints'*)
        printf '%s\\n' ca >>"$VERIFY_LOG"
        [[ ${VERIFY_FAILURE:-} == ca ]] || printf '%s\\n' 'CA:FALSE'
        ;;
      *'extendedKeyUsage'*)
        printf '%s\\n' eku >>"$VERIFY_LOG"
        [[ ${VERIFY_FAILURE:-} == eku ]] || printf '%s\\n' 'TLS Web Server Authentication'
        ;;
      *'subjectAltName'*)
        if [[ $(tail -n 1 "$VERIFY_LOG") == eku ]]; then
          printf '%s\\n' dns >>"$VERIFY_LOG"
          [[ ${VERIFY_FAILURE:-} == dns ]] || printf '%s\\n' 'DNS:platform.example.internal'
        else
          printf '%s\\n' ip >>"$VERIFY_LOG"
          [[ ${VERIFY_FAILURE:-} == ip ]] || printf '%s\\n' 'IP Address:192.0.2.10'
        fi
        ;;
      *'-checkend'*)
        printf '%s\\n' lifetime >>"$VERIFY_LOG"
        [[ ${VERIFY_FAILURE:-} != lifetime ]] || exit 1
        ;;
    esac
    ;;
esac
"""
PIPELINE_OPENSSL = """#!/usr/bin/env bash
set -euo pipefail
printf 'openssl %s\\n' "$*" >>"$VERIFY_LOG"
case $1 in
  verify) exit 0 ;;
  pkey) printf '%s\\n' 'matching-public-key' ;;
  x509)
    case $* in
      *'-pubkey'*) printf '%s\\n' 'matching-public-key' ;;
      *'basicConstraints'*)
        printf '%s\\n' 'CA:FALSE'
        printf '%s\\n' 'extension read failed' >&2
        exit 7
        ;;
    esac
    ;;
esac
"""
PIPELINE_GREP = """#!/usr/bin/env bash
set -euo pipefail
printf 'grep %s\\n' "$*" >>"$VERIFY_LOG"
/usr/bin/grep "$@"
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
        REAL_COMMON=os.fspath(
            ROOT / "tests/pki/oracles/final-bash-source/lib/platform-pki-common.sh"
        ),
        PLATFORM_TOOLS_LIB_DIR=os.fspath(fake_library.parent),
        VERIFY_FAILURE=failure,
        VERIFY_LOG=os.fspath(log),
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
        effective_environment.setdefault(
            "PLATFORM_TOOLS_LIB_DIR",
            os.fspath(ROOT / "tests/pki/oracles/final-bash-source/lib"),
        )
    return process_runner([*command, *arguments], env=effective_environment)


OPERATIONAL_TOOLS = (
    pytest.param((ORACLE,), id="bash-oracle"),
    pytest.param((TOOL,), id="python-compatibility"),
    pytest.param((UNIFIED, "service-verify"), id="python-unified"),
)


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


def test_frozen_oracle_matches_recorded_provenance() -> None:
    assert hashlib.sha256(ORACLE.read_bytes()).hexdigest() == ORACLE_SHA256
    assert ORACLE_COMMIT in (
        ROOT / "docs/plans/platform-pki-python-migration.md"
    ).read_text(encoding="utf-8")


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


@pytest.mark.parametrize("tool", OPERATIONAL_TOOLS)
def test_invalid_service_name(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    tool: tuple[Path | str, ...],
) -> None:
    pki, _, _ = _workspace(tmp_path)
    result = _run(process_runner, ["bad/name", "--pki-dir", pki], tool=tool)
    assert result.status == 1
    assert result.stdout == ""
    assert "Invalid service name: bad/name" in result.stderr


@pytest.mark.parametrize("tool", OPERATIONAL_TOOLS)
def test_successful_verification_order(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    tool: tuple[Path | str, ...],
) -> None:
    pki, fake_library, fake_bin = _workspace(tmp_path)
    environment, log = _environment(tmp_path, fake_library, fake_bin, "none")

    result = _run(
        process_runner,
        ["platform-example", "--pki-dir", pki, "--min-days", "30"],
        environment,
        tool,
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
@pytest.mark.parametrize("tool", OPERATIONAL_TOOLS)
def test_application_verification_failure_stops_in_order(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    failure: str,
    message: str,
    order: str,
    tool: tuple[Path | str, ...],
) -> None:
    pki, fake_library, fake_bin = _workspace(tmp_path)
    environment, log = _environment(tmp_path, fake_library, fake_bin, failure)

    result = _run(
        process_runner,
        ["platform-example", "--pki-dir", pki, "--min-days", "30"],
        environment,
        tool,
    )

    assert result.status == 1
    assert result.stdout == ""
    assert message in result.stderr
    assert result.stderr.startswith("[ERROR] ")
    assert result.stderr.endswith("\n")
    assert result.stderr.count("\n") == 1
    assert log.read_text(encoding="utf-8") == order


@pytest.mark.parametrize("tool", OPERATIONAL_TOOLS)
def test_openssl_trust_failure_preserves_child_stderr(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    tool: tuple[Path | str, ...],
) -> None:
    pki, fake_library, fake_bin = _workspace(tmp_path)
    environment, log = _environment(tmp_path, fake_library, fake_bin, "trust")

    result = _run(
        process_runner,
        ["platform-example", "--pki-dir", pki, "--min-days", "30"],
        environment,
        tool,
    )

    assert result == ProcessResult(
        result.args, 1, "", "certificate chain verification failed\n"
    )
    assert log.read_text(encoding="utf-8") == "trust\ntrust\n"


@pytest.mark.parametrize("tool", OPERATIONAL_TOOLS)
def test_extension_openssl_failure_still_runs_grep(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    tool: tuple[Path | str, ...],
) -> None:
    pki, _, fake_bin = _workspace(tmp_path)
    _write(fake_bin / "openssl", PIPELINE_OPENSSL, 0o755)
    _write(fake_bin / "grep", PIPELINE_GREP, 0o755)
    log = tmp_path / "pipeline.log"
    environment = dict(
        os.environ,
        PATH=f"{fake_bin}:{os.environ['PATH']}",
        PLATFORM_TOOLS_LIB_DIR=os.fspath(
            ROOT / "tests/pki/oracles/final-bash-source/lib"
        ),
        VERIFY_LOG=os.fspath(log),
    )

    result = _run(
        process_runner,
        ["platform-example", "--pki-dir", pki, "--min-days", "30"],
        environment,
        tool,
    )

    assert result.status == 1
    assert result.stdout == ""
    assert result.stderr == (
        "extension read failed\n"
        "[ERROR] Certificate is missing CA:false: "
        f"{pki}/services/platform-example/certs/tls.crt\n"
    )
    assert sorted(log.read_text(encoding="utf-8").splitlines()[-2:]) == sorted([
        "openssl x509 -in "
        f"{pki}/services/platform-example/certs/tls.crt -noout -ext basicConstraints",
        "grep -F CA:FALSE",
    ])


@pytest.mark.parametrize("tool", OPERATIONAL_TOOLS)
def test_unknown_service_stops_after_active_issuer_validation(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    tool: tuple[Path | str, ...],
) -> None:
    pki, fake_library, fake_bin = _workspace(tmp_path)
    environment, log = _environment(tmp_path, fake_library, fake_bin, "unknown")

    result = _run(
        process_runner, ["unknown-service", "--pki-dir", pki], environment, tool
    )

    assert result.status == 1
    assert result.stdout == ""
    assert "Service is not defined in" in result.stderr
    assert log.read_text(encoding="utf-8") == "trust\n"


@pytest.mark.parametrize("tool", OPERATIONAL_TOOLS)
def test_host_local_service_verification_fails_closed(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    tool: tuple[Path | str, ...],
) -> None:
    pki, fake_library, fake_bin = _workspace(tmp_path)
    _write(
        pki / "inventory/services.yml",
        INVENTORY.replace(
            "  platform-example:\n",
            "  platform-example:\n    key_custody: host-local\n"
            "    target: host-01\n"
            "    validation_boundary_sha256: 0000000000000000000000000000000000000000000000000000000000000000\n"
            "    rollback_hold_seconds: 3600\n",
        ),
    )
    environment, log = _environment(tmp_path, fake_library, fake_bin, "none")

    result = _run(
        process_runner, ["platform-example", "--pki-dir", pki], environment, tool
    )

    assert result.status == 1
    assert result.stdout == ""
    assert "Host-local signer-side candidate verification is unavailable: platform-example" in result.stderr
    assert log.read_text(encoding="utf-8") == "trust\n"


def test_bash_python_success_state_and_output_are_equivalent(tmp_path: Path) -> None:
    seed = tmp_path / "seed"
    seed.mkdir(mode=0o700)
    pki, fake_library, fake_bin = _workspace(seed)
    environment, _ = _environment(tmp_path, fake_library, fake_bin, "none")

    result = run_differential_case(
        seed,
        tmp_path / "case",
        Path("pki"),
        lambda root: (
            ORACLE,
            "platform-example",
            "--pki-dir",
            root / "pki",
        ),
        lambda root: (
            UNIFIED,
            "service-verify",
            "platform-example",
            "--pki-dir",
            root / "pki",
        ),
        environment,
        run_options={"timeout": 30},
    )

    result.assert_equivalent()


def test_missing_installed_share_library_is_ignored(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
    pki, fake_library, fake_bin = _workspace(tmp_path)
    tool = tmp_path / "installed/bin/platform-pki-service-verify"
    tool.parent.mkdir(mode=0o700, parents=True)
    shutil.copy2(TOOL, tool)
    environment, _ = _environment(tmp_path, fake_library, fake_bin, "none")
    environment = dict(environment)
    environment.pop("PLATFORM_TOOLS_LIB_DIR")
    environment["PLATFORM_TOOLS_SHARE_DIR"] = os.fspath(tmp_path / "installed/share")

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


def test_command_operates_without_shared_library(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
    pki, fake_library, fake_bin = _workspace(tmp_path)
    tool, isolated = _isolated_tool(tmp_path)
    environment, _ = _environment(tmp_path, fake_library, fake_bin, "none")
    environment = dict(environment)
    environment.pop("PLATFORM_TOOLS_LIB_DIR")
    environment["HOME"] = isolated["HOME"]
    environment["PLATFORM_TOOLS_SHARE_DIR"] = isolated["PLATFORM_TOOLS_SHARE_DIR"]

    result = _run(process_runner, ["platform-example", "--pki-dir", pki], environment, tool)

    assert result == ProcessResult(
        result.args, 0, "[OK] Verified service certificate: platform-example\n", ""
    )
