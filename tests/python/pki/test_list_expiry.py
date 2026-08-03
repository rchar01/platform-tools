from __future__ import annotations

import os
import shutil
import tempfile
from collections.abc import Callable, Iterator, Mapping, Sequence
from pathlib import Path

import pytest

from ..harness import ProcessResult, run_process


ROOT = Path(__file__).resolve().parents[3]
TOOL = ROOT / "bin/platform-pki-list-expiry"
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
HEADER = f"{'SERVICE':24} {'EXPIRES':22} {'DAYS_LEFT':10} STATUS\n"
FAKE_COMMON = """# shellcheck source=../../../../lib/platform-pki-common.sh
source "$REAL_COMMON"

pki_cert_days_left() {
  case $1 in
    *critical-boundary*) printf '%s\\n' '30' ;;
    *warn-boundary*) printf '%s\\n' '90' ;;
    *) printf '%s\\n' '120' ;;
  esac
}

pki_cert_not_after_iso() {
  printf '%s\\n' '2027-07-26T00:00:00Z'
}
"""


@pytest.fixture
def tmp_path() -> Iterator[Path]:
    temporary_root = ROOT / ".tmp"
    temporary_root.mkdir(mode=0o700, exist_ok=True)
    path = Path(tempfile.mkdtemp(prefix="pytest-list-expiry.", dir=temporary_root))
    path.chmod(0o700)
    yield path
    shutil.rmtree(path)


def _write(path: Path, content: str, mode: int = 0o600) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    path.chmod(mode)


@pytest.fixture(scope="module")
def authority_certificates(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    root = tmp_path_factory.mktemp("list-expiry-authorities")
    root_key = root / "root.key"
    root_cert = root / "root.crt"
    intermediate_key = root / "intermediate.key"
    intermediate_request = root / "intermediate.csr"
    intermediate_cert = root / "intermediate.crt"
    commands = (
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "365",
            "-subj", "/CN=TestRoot", "-keyout", root_key, "-out", root_cert,
        ],
        [
            "openssl", "req", "-newkey", "rsa:2048", "-nodes", "-subj",
            "/CN=TestIntermediate", "-keyout", intermediate_key, "-out", intermediate_request,
        ],
        [
            "openssl", "x509", "-req", "-in", intermediate_request, "-CA", root_cert,
            "-CAkey", root_key, "-CAcreateserial", "-days", "300", "-out", intermediate_cert,
        ],
    )
    for command in commands:
        result = run_process(command, timeout=30)
        assert result.status == 0, result.stderr
    return root_cert, intermediate_cert


def _inventory(
    pki: Path,
    service: str,
    authority_certificates: tuple[Path, Path],
) -> None:
    root_cert, intermediate_cert = authority_certificates
    for relative in (
        "inventory",
        "authorities/roots/g1/certs",
        "authorities/intermediates/g1-i1/certs",
        "locks",
        "state/rollover",
    ):
        (pki / relative).mkdir(mode=0o700, parents=True, exist_ok=True)
    for directory in (pki, *(path for path in pki.rglob("*") if path.is_dir())):
        directory.chmod(0o700)
    shutil.copy2(root_cert, pki / "authorities/roots/g1/certs/root-ca.crt")
    shutil.copy2(
        intermediate_cert,
        pki / "authorities/intermediates/g1-i1/certs/intermediate-ca.crt",
    )
    _write(pki / "state/active-issuer", "root=g1\nintermediate=g1-i1\n")
    _write(
        pki / "inventory/services.yml",
        f"services:\n  {service}:\n    common_name: {service}.example.internal\n"
        f"    dns:\n      - {service}.example.internal\n",
    )


def _certificate(
    pki: Path,
    service: str,
    days: int,
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
) -> None:
    certificate = pki / f"services/{service}/certs/tls.crt"
    certificate.parent.mkdir(mode=0o700, parents=True)
    result = process_runner(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", str(days),
            "-subj", f"/CN={service}.example.internal", "-keyout", tmp_path / f"{service}.key",
            "-out", certificate,
        ]
    )
    assert result.status == 0, result.stderr


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
    assert "platform-pki-list-expiry --version | -v" in result.stdout
    assert result.stderr == ""


def test_version(process_runner: Callable[..., ProcessResult]) -> None:
    result = _run(process_runner, ["--version"])
    assert result == ProcessResult(
        result.args, 0, f"platform-pki-list-expiry {VERSION}\n", ""
    )


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        pytest.param(["--unknown"], "invalid option: --unknown", id="unknown-option"),
        pytest.param(["--warn-days", "nope"], "Days value must be numeric: nope", id="nonnumeric-warn-days"),
        pytest.param(["--critical-days", "0"], "Days value must be at least 1: 0", id="zero-critical-days"),
    ],
)
def test_argument_errors(
    process_runner: Callable[..., ProcessResult], arguments: list[str], message: str
) -> None:
    result = _run(process_runner, arguments)
    assert result.status == 1
    assert result.stdout == ""
    assert message in result.stderr


def test_missing_pki_directory(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
    result = _run(process_runner, ["--pki-dir", tmp_path / "does-not-exist"])
    assert result.status == 1
    assert result.stdout == ""
    assert "PKI directory does not exist" in result.stderr


@pytest.mark.parametrize(
    ("name", "days", "status", "exit_status"),
    [
        pytest.param("ok-service", 120, "OK", 0, id="ok"),
        pytest.param("warn-service", 60, "WARN", 1, id="warn"),
        pytest.param("critical-service", 10, "CRITICAL", 2, id="critical"),
    ],
)
def test_real_certificate_lifetime_classification(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    authority_certificates: tuple[Path, Path],
    name: str,
    days: int,
    status: str,
    exit_status: int,
) -> None:
    pki = tmp_path / name
    _inventory(pki, name, authority_certificates)
    _certificate(pki, name, days, tmp_path, process_runner)

    result = _run(
        process_runner,
        ["--pki-dir", pki, "--warn-days", "90", "--critical-days", "30"],
    )

    assert result.status == exit_status
    assert result.stderr == ""
    lines = result.stdout.splitlines()
    assert lines[0] == HEADER.rstrip("\n")
    fields = lines[1].split()
    assert fields[0] == name
    assert fields[-1] == status


def test_missing_certificate_status(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    authority_certificates: tuple[Path, Path],
) -> None:
    pki = tmp_path / "missing"
    _inventory(pki, "missing-service", authority_certificates)

    result = _run(process_runner, ["--pki-dir", pki])

    assert result.status == 3
    assert result.stderr == ""
    assert result.stdout == HEADER + f"{'missing-service':24} {'-':22} {'-':10} MISSING\n"


def _mixed_inventory(
    pki: Path,
    first: str,
    second: str,
    authority_certificates: tuple[Path, Path],
) -> None:
    _inventory(pki, first, authority_certificates)
    _write(
        pki / "inventory/services.yml",
        "services:\n"
        f"  {first}:\n    common_name: {first}.example.internal\n    dns:\n      - {first}.example.internal\n"
        "  warn-boundary:\n    common_name: warn.example.internal\n    dns:\n      - warn.example.internal\n"
        f"  {second}:\n    common_name: {second}.example.internal\n    dns:\n      - {second}.example.internal\n",
    )
    for service in ("critical-boundary", "warn-boundary"):
        _write(pki / f"services/{service}/certs/tls.crt", "", 0o644)


@pytest.mark.parametrize(
    ("first", "second"),
    [
        pytest.param("missing-service", "critical-boundary", id="missing-first"),
        pytest.param("critical-boundary", "missing-service", id="missing-last"),
    ],
)
def test_missing_status_dominates_regardless_of_inventory_order(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    authority_certificates: tuple[Path, Path],
    first: str,
    second: str,
) -> None:
    order = "first" if first == "missing-service" else "last"
    pki = tmp_path / f"mixed-missing-{order}"
    _mixed_inventory(pki, first, second, authority_certificates)
    fake_library = tmp_path / f"fake-lib-{first}/platform-pki-common.sh"
    _write(fake_library, FAKE_COMMON, 0o644)
    environment = dict(
        os.environ,
        REAL_COMMON=os.fspath(ROOT / "lib/platform-pki-common.sh"),
        PLATFORM_TOOLS_LIB_DIR=os.fspath(fake_library.parent),
    )

    result = _run(
        process_runner,
        ["--pki-dir", pki, "--warn-days", "90", "--critical-days", "30"],
        environment,
    )

    expected_rows = {
        "missing-service": f"{'missing-service':24} {'-':22} {'-':10} MISSING\n",
        "warn-boundary": f"{'warn-boundary':24} {'2027-07-26T00:00:00Z':22} {'90':10} WARN\n",
        "critical-boundary": f"{'critical-boundary':24} {'2027-07-26T00:00:00Z':22} {'30':10} CRITICAL\n",
    }
    assert result.status == 3
    assert result.stderr == ""
    assert result.stdout == HEADER + "".join(
        expected_rows[service] for service in (first, "warn-boundary", second)
    )


def test_installed_share_directory_layout(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    authority_certificates: tuple[Path, Path],
) -> None:
    pki = tmp_path / "ok"
    _inventory(pki, "ok-service", authority_certificates)
    _certificate(pki, "ok-service", 120, tmp_path, process_runner)
    tool = tmp_path / "installed/bin/platform-pki-list-expiry"
    tool.parent.mkdir(mode=0o700, parents=True)
    library = tmp_path / "installed/share/lib/platform-pki-common.sh"
    library.parent.mkdir(mode=0o700, parents=True)
    shutil.copy2(TOOL, tool)
    shutil.copy2(ROOT / "lib/platform-pki-common.sh", library)
    environment = dict(os.environ, PLATFORM_TOOLS_SHARE_DIR=os.fspath(library.parents[1]))

    result = _run(process_runner, ["--pki-dir", pki], environment, tool)

    assert result.status == 0
    assert result.stderr == ""
    assert "ok-service" in result.stdout


def _isolated_tool(tmp_path: Path) -> tuple[Path, Mapping[str, str]]:
    tool = tmp_path / "isolated/bin/platform-pki-list-expiry"
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
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    authority_certificates: tuple[Path, Path],
) -> None:
    pki = tmp_path / "ok"
    _inventory(pki, "ok-service", authority_certificates)
    _certificate(pki, "ok-service", 120, tmp_path, process_runner)
    tool, environment = _isolated_tool(tmp_path)

    result = _run(process_runner, ["--pki-dir", pki], environment, tool)

    assert result.status == 1
    assert result.stdout == ""
    assert "platform-pki-common.sh not found" in result.stderr
