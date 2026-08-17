from __future__ import annotations

import json
import fcntl
import os
import shutil
import tempfile
from collections.abc import Callable
from hashlib import sha256
from pathlib import Path
from typing import Any

import pytest

from ..harness import ProcessResult
from .migration_harness import run_differential_case
from src.platform_pki import custody_report, filesystem
from src.platform_pki.errors import ApplicationError
from src.platform_pki.filesystem import (
    DirectoryPolicy,
    FilePolicy,
    FilesystemIdentityError,
    FilesystemTraversalError,
    OpenedDirectory,
    OpenedFile,
    open_descendant_file,
    walk_metadata,
)
from src.platform_pki.subprocesses import ProcessOutputOverflowError, ProcessTimeoutError


ROOT = Path(__file__).resolve().parents[2]
TOOL = (ROOT / "bin/platform-pki", "custody-report")
ORACLE = ROOT / "tests/pki/oracles/platform-pki-custody-report/platform-pki-custody-report"
ORACLE_COMMIT = "a2336a1518d41bf5dd2c5f2897a0c1c84128b5f4"
ORACLE_SHA256 = "f17aa588e5d6d200f16c3ae416da15a18c839f29ae97963704d5f11b27f822e4"
COMMON_SHA256 = "dee644be8ab6236cb368a553493f55b53a90c3aead291550f7e635c080a5494f"
PYTHON_INTERFACES = (
    pytest.param(TOOL, id="unified"),
)
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
ROOT_SECRET = "root-private-parameters-must-not-appear"
INTERMEDIATE_SECRET = "intermediate-private-parameters-must-not-appear"
SERVICE_SECRET = "service-private-parameters-must-not-appear"
EXPORT_SECRET = "export-private-parameters-must-not-appear"


def _write(path: Path, content: str, mode: int = 0o600) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    path.chmod(mode)


def _private_key(path: Path, *, encrypted: bool, secret: str) -> None:
    header = "ENCRYPTED PRIVATE KEY" if encrypted else "PRIVATE KEY"
    _write(path, f"-----BEGIN {header}-----\n{secret}\n-----END {header}-----\n")


def _receipt(archive: Path, *, layout: str = "generation") -> None:
    metadata = archive.stat()
    digest = "0" * 64
    _write(
        Path(f"{archive}.receipt"),
        "\n".join(
            (
                "schema=2",
                f"layout={layout}",
                f"session={'0' * 32}",
                f"backup_path={archive}",
                f"backup_device={metadata.st_dev}",
                f"backup_inode={metadata.st_ino}",
                f"backup_size={metadata.st_size}",
                "backup_mode=600",
                f"backup_owner={metadata.st_uid}",
                f"archive_sha256={digest}",
                "created_at=2026-08-05T12:00:00Z",
                "created_epoch=1785931200",
                f"state_manifest_sha256={digest}",
                f"private_metadata_sha256={digest}",
                "",
            )
        ),
    )


def _workspace(tmp_path: Path, *, leaf_keys: bool = True, backup: bool = True) -> Path:
    pki = tmp_path / "pki"
    directories = (
        "authorities/roots/g1/private",
        "authorities/intermediates/g1-i1/private",
        "state",
        "locks",
        "inventory",
    )
    for relative in directories:
        (pki / relative).mkdir(mode=0o700, parents=True, exist_ok=True)
    for directory in (pki, *(path for path in pki.rglob("*") if path.is_dir())):
        directory.chmod(0o700)
    _write(pki / "state/active-issuer", "root=g1\nintermediate=g1-i1\n")
    _private_key(
        pki / "authorities/roots/g1/private/root-ca.key",
        encrypted=True,
        secret=ROOT_SECRET,
    )
    _private_key(
        pki / "authorities/intermediates/g1-i1/private/intermediate-ca.key",
        encrypted=True,
        secret=INTERMEDIATE_SECRET,
    )
    if leaf_keys:
        _private_key(
            pki / "services/app/private/tls.key",
            encrypted=False,
            secret=SERVICE_SECRET,
        )
        _private_key(
            pki / "export/ansible/services/app/tls.key",
            encrypted=False,
            secret=EXPORT_SECRET,
        )
    if backup:
        archive = pki / "backups/platform-pki-20260805-120000.tar.gz.age"
        _write(archive, "age-encryption.org/v1\nopaque-encrypted-payload\n")
        _receipt(archive)
    for directory in (pki, *(path for path in pki.rglob("*") if path.is_dir())):
        directory.chmod(0o700)
    return pki


def _legacy_workspace(tmp_path: Path) -> Path:
    pki = tmp_path / "legacy-pki"
    for relative in ("root-ca/private", "intermediate-ca/private", "locks", "state"):
        (pki / relative).mkdir(mode=0o700, parents=True, exist_ok=True)
    for directory in (pki, *(path for path in pki.rglob("*") if path.is_dir())):
        directory.chmod(0o700)
    _private_key(pki / "root-ca/private/root-ca.key", encrypted=True, secret=ROOT_SECRET)
    _private_key(
        pki / "intermediate-ca/private/intermediate-ca.key",
        encrypted=True,
        secret=INTERMEDIATE_SECRET,
    )
    return pki


def _run(
    process_runner: Callable[..., ProcessResult],
    pki: Path,
    *arguments: str,
) -> ProcessResult:
    return process_runner([*TOOL, "--pki-dir", pki, *arguments], timeout=30)


def _run_interface(
    process_runner: Callable[..., ProcessResult],
    command: tuple[Path | str, ...],
    pki: Path,
    *arguments: str,
    env: dict[str, str] | None = None,
) -> ProcessResult:
    environment = dict(os.environ if env is None else env)
    if command == (ORACLE,):
        environment["PLATFORM_TOOLS_LIB_DIR"] = os.fspath(
            ROOT / "tests/pki/oracles/final-bash-source/lib"
        )
    return process_runner(
        [*command, "--pki-dir", pki, *arguments], env=environment, timeout=30
    )


def _material(report: dict[str, object], material_id: str) -> dict[str, str]:
    materials = report["materials"]
    assert isinstance(materials, list)
    matches = [item for item in materials if item["id"] == material_id]
    assert len(matches) == 1
    return matches[0]


def _finding_codes(report: dict[str, object]) -> set[str]:
    findings = report["findings"]
    assert isinstance(findings, list)
    return {finding["code"] for finding in findings}


def _sensitive_snapshot(pki: Path) -> dict[str, tuple[int, int, int, str]]:
    snapshot: dict[str, tuple[int, int, int, str]] = {}
    for path in sorted(pki.rglob("*")):
        if not path.is_file() or path.is_symlink() or path.is_relative_to(pki / "locks"):
            continue
        relative = path.relative_to(pki).as_posix()
        if relative.startswith("state/") and relative != "state/active-issuer":
            continue
        metadata = path.stat()
        snapshot[relative] = (
            metadata.st_mode,
            metadata.st_size,
            metadata.st_mtime_ns,
            sha256(path.read_bytes()).hexdigest(),
        )
    return snapshot


def test_help_and_version(process_runner: Callable[..., ProcessResult]) -> None:
    help_result = process_runner([*TOOL, "--help"])
    assert help_result.status == 0
    assert "only the first PEM header line" in help_result.stdout
    assert help_result.stderr == ""

    version_result = process_runner([TOOL[0], "--version"])
    assert version_result.status == 0
    assert version_result.stdout == f"platform-pki {VERSION}\n"
    assert version_result.stderr == ""


def test_frozen_oracle_and_common_library_match_recorded_provenance() -> None:
    plan = (ROOT / "docs/plans/platform-pki-python-migration.md").read_text(encoding="utf-8")
    assert sha256(ORACLE.read_bytes()).hexdigest() == ORACLE_SHA256
    assert sha256((ROOT / "tests/pki/oracles/final-bash-source/lib/platform-pki-common.sh").read_bytes()).hexdigest() == COMMON_SHA256
    assert ORACLE_COMMIT in plan
    assert os.access(ORACLE, os.X_OK)


@pytest.mark.parametrize("command", PYTHON_INTERFACES)
@pytest.mark.parametrize("report_format", ("text", "json"))
def test_clean_generation_reports_match_frozen_oracle_bytes(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    command: tuple[Path | str, ...],
    report_format: str,
) -> None:
    pki = _workspace(tmp_path, leaf_keys=False, backup=False)
    oracle = _run_interface(process_runner, (ORACLE,), pki, "--format", report_format)
    result = _run_interface(process_runner, command, pki, "--format", report_format)
    assert (result.status, result.stdout, result.stderr) == (
        oracle.status,
        oracle.stdout,
        oracle.stderr,
    )


@pytest.mark.parametrize("command", PYTHON_INTERFACES)
def test_findings_report_matches_frozen_oracle_bytes(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    command: tuple[Path | str, ...],
) -> None:
    pki = _workspace(tmp_path)
    oracle = _run_interface(process_runner, (ORACLE,), pki, "--format", "json")
    result = _run_interface(process_runner, command, pki, "--format", "json")
    assert (result.status, result.stdout, result.stderr) == (
        oracle.status,
        oracle.stdout,
        oracle.stderr,
    )


@pytest.mark.parametrize("command", PYTHON_INTERFACES)
def test_clean_generation_process_and_state_match_frozen_oracle(
    tmp_path: Path,
    command: tuple[Path | str, ...],
) -> None:
    seed = tmp_path / "seed"
    _workspace(seed, leaf_keys=False, backup=False)
    environment = {**os.environ, "PLATFORM_TOOLS_LIB_DIR": os.fspath(ROOT / "tests/pki/oracles/final-bash-source/lib")}
    result = run_differential_case(
        seed,
        tmp_path / f"case-{Path(command[0]).name}",
        Path("pki"),
        lambda root: (ORACLE, "--pki-dir", root / "pki", "--format", "json"),
        lambda root: (*command, "--pki-dir", root / "pki", "--format", "json"),
        environment,
        run_options={"timeout": 30},
    )
    result.assert_equivalent()


@pytest.mark.parametrize("command", PYTHON_INTERFACES)
@pytest.mark.parametrize(
    "active_issuer",
    (
        pytest.param(b"root=g1\r\nintermediate=g1-i1\r\n", id="crlf"),
        pytest.param(b"root=g1\nintermediate=g1-i1", id="unterminated-second-line"),
        pytest.param(
            b"root=g1\nintermediate=g1-i1\nignored", id="unterminated-third-line"
        ),
    ),
)
def test_active_issuer_line_termination_matches_frozen_oracle(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    command: tuple[Path | str, ...],
    active_issuer: bytes,
) -> None:
    pki = _workspace(tmp_path, leaf_keys=False, backup=False)
    path = pki / "state/active-issuer"
    path.write_bytes(active_issuer)
    path.chmod(0o600)
    oracle = _run_interface(process_runner, (ORACLE,), pki, "--format", "json")
    result = _run_interface(process_runner, command, pki, "--format", "json")
    assert (result.status, result.stdout, result.stderr) == (
        oracle.status,
        oracle.stdout,
        oracle.stderr,
    )


def test_rejects_unknown_format(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
    result = _run(process_runner, tmp_path / "unused", "--format", "yaml")
    assert result.status == 1
    assert result.stdout == ""
    assert "Format must be text or json: yaml" in result.stderr
    assert not (tmp_path / "unused").exists()


def test_json_classifies_managed_material_without_disclosing_secrets(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
    pki = _workspace(tmp_path)
    result = _run(process_runner, pki, "--format", "json")

    assert result.status == 2
    assert result.stderr == ""
    report = json.loads(result.stdout)
    assert report["schema"] == 1
    assert report["status"] == "findings"
    assert report["layout"] == "generation"
    assert report["storage_encryption_evidence"] in {"luks-ancestor", "no-luks-ancestor", "unknown"}
    assert _material(report, "root:g1")["encryption_evidence"] == "encrypted-pkcs8-header"
    assert _material(report, "intermediate:g1-i1")["encryption_evidence"] == "encrypted-pkcs8-header"
    assert _material(report, "service:app") == {
        "id": "service:app",
        "role": "controller-leaf-key",
        "encryption_evidence": "plaintext-pkcs8-header",
        "recommended_custody": "target-host-only",
        "backup_policy": "reissue-with-fresh-key",
        "status": "finding",
    }
    assert _material(report, "export:app")["role"] == "ansible-export-key"
    assert _material(report, "backup:20260805-120000:age")["encryption_evidence"] == "age-v1-header"
    assert {"controller-leaf-key", "duplicate-export-key"} <= _finding_codes(report)
    assert set(report["operational_checks"].values()) == {"unknown"}
    combined = result.stdout + result.stderr
    for secret in (ROOT_SECRET, INTERMEDIATE_SECRET, SERVICE_SECRET, EXPORT_SECRET):
        assert secret not in combined


def test_json_classifies_host_local_candidate_and_protocol_state(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
    pki = _workspace(tmp_path, leaf_keys=False, backup=False)
    _write(
        pki / "state/csr/candidates/external/0123456789abcdef0123456789abcdef/candidate",
        "schema=1\nstate=pending\n",
    )
    _write(
        pki / "state/csr/responses/external/0123456789abcdef0123456789abcdef/response",
        "schema=1\ncandidate_state=pending\n",
    )
    for directory in (path for path in (pki / "state/csr").rglob("*") if path.is_dir()):
        directory.chmod(0o700)
    (pki / "state/csr").chmod(0o700)

    result = _run(process_runner, pki, "--format", "json")

    assert result.status == 0
    report = json.loads(result.stdout)
    assert _material(report, "host-local-csr-state") == {
        "id": "host-local-csr-state",
        "role": "certificate-only-candidates-and-protocol-evidence",
        "encryption_evidence": "not-required",
        "recommended_custody": "controlled-protocol-state",
        "backup_policy": "encrypted-state-backup",
        "status": "review",
    }
    assert "unexpected-keys" not in _finding_codes(report)


def test_text_report_has_stable_sections(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
    result = _run(process_runner, _workspace(tmp_path))
    assert result.status == 2
    assert result.stderr == ""
    assert result.stdout.startswith("status=findings\nlayout=generation\n")
    assert "\t" not in result.stdout
    lines = result.stdout.splitlines()
    material_header = next(line for line in lines if line.startswith("MATERIAL "))
    material_row = next(line for line in lines if line.startswith("root:g1 "))
    for heading in ("ROLE", "ENCRYPTION_EVIDENCE", "RECOMMENDED_CUSTODY", "BACKUP_POLICY", "STATUS"):
        assert material_header.index(heading) == material_row.index(
            {
                "ROLE": "root-authority",
                "ENCRYPTION_EVIDENCE": "encrypted-pkcs8-header",
                "RECOMMENDED_CUSTODY": "offline-detached",
                "BACKUP_POLICY": "two-encrypted-separated",
                "STATUS": "review",
            }[heading]
        )
    finding_header = next(line for line in lines if line.startswith("SEVERITY "))
    finding_row = next(line for line in lines if line.startswith("medium "))
    assert finding_header.index("CODE") == finding_row.index("controller-leaf-key")
    assert finding_header.index("MATERIAL") == finding_row.index("service:app")
    assert finding_header.index("ACTION") == finding_row.index("migrate-to-host-local-key")
    assert "\nOPERATIONAL_CHECKS\nca_key_cryptographic_validation=unknown\n" in result.stdout
    assert "offline_ca_custody=unknown\n" in result.stdout


def test_report_can_be_structurally_clean_without_leaf_or_local_backup_keys(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
    result = _run(
        process_runner,
        _workspace(tmp_path, leaf_keys=False, backup=False),
        "--format",
        "json",
    )
    assert result.status == 0
    report = json.loads(result.stdout)
    assert report["status"] == "ok"
    assert report["findings"] == []
    assert _material(report, "root:g1")["status"] == "review"
    assert report["operational_checks"]["ca_key_cryptographic_validation"] == "unknown"


def test_plaintext_ca_key_is_high_severity_finding(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
    pki = _workspace(tmp_path, leaf_keys=False, backup=False)
    _private_key(
        pki / "authorities/roots/g1/private/root-ca.key",
        encrypted=False,
        secret=ROOT_SECRET,
    )
    result = _run(process_runner, pki, "--format", "json")
    report = json.loads(result.stdout)
    assert result.status == 2
    assert _material(report, "root:g1")["encryption_evidence"] == "plaintext-pkcs8-header"
    findings = report["findings"]
    assert {
        (item["severity"], item["code"], item["material"])
        for item in findings
    } >= {("high", "ca-key-encryption-header-missing", "root:g1")}


def test_overlong_private_key_header_is_bounded_and_reported(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
    pki = _workspace(tmp_path, leaf_keys=False, backup=False)
    key = pki / "authorities/roots/g1/private/root-ca.key"
    _write(key, f"{'A' * 4096}\n{ROOT_SECRET}\n")

    result = _run(process_runner, pki, "--format", "json")
    report = json.loads(result.stdout)
    assert result.status == 2
    assert "oversized-private-key-header" in _finding_codes(report)
    assert _material(report, "root:g1")["encryption_evidence"] == "overlong-header"
    assert ROOT_SECRET not in result.stdout + result.stderr


@pytest.mark.parametrize(
    ("length", "expected"),
    ((255, "unknown"), (256, "unknown"), (257, "overlong-header")),
)
def test_first_line_exact_length_boundaries(
    tmp_path: Path, length: int, expected: str
) -> None:
    path = tmp_path / f"header-{length}"
    path.write_bytes(b"A" * length + b"\nprivate-tail-must-not-be-read")
    with OpenedFile(path) as opened:
        assert custody_report._classify_first_line(opened, "key", "private key") == expected


def test_first_line_nul_precedes_overlong_and_large_tail_is_not_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    nul = tmp_path / "nul"
    nul.write_bytes(b"A" * 256 + b"\0" + b"private-tail-must-not-be-read" * 1000)
    with OpenedFile(nul) as opened:
        assert custody_report._classify_first_line(opened, "key", "private key") == "nul-header"

    large = tmp_path / "large"
    large.write_bytes(
        b"-----BEGIN ENCRYPTED PRIVATE KEY-----\n" + b"private-tail-must-not-be-read" * 400000
    )
    requests: list[int] = []
    real_pread = os.pread

    def recording_pread(fd: int, size: int, offset: int) -> bytes:
        requests.append(size)
        return real_pread(fd, size, offset)

    monkeypatch.setattr(filesystem.os, "pread", recording_pread)
    with OpenedFile(large) as opened:
        assert (
            custody_report._classify_first_line(opened, "key", "private key")
            == "encrypted-pkcs8-header"
        )
    assert requests == [257]


def test_nul_heavy_private_key_header_is_byte_bounded_and_reported(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
    pki = _workspace(tmp_path, leaf_keys=False, backup=False)
    key = pki / "authorities/roots/g1/private/root-ca.key"
    key.write_bytes(b"\x00" * 10000 + ROOT_SECRET.encode())
    key.chmod(0o600)

    result = _run(process_runner, pki, "--format", "json")
    report = json.loads(result.stdout)
    assert result.status == 2
    assert "binary-private-key-header" in _finding_codes(report)
    assert _material(report, "root:g1")["encryption_evidence"] == "nul-header"
    assert ROOT_SECRET not in result.stdout + result.stderr


@pytest.mark.parametrize("unsafe_kind", ("symlink", "hardlink", "open-mode"))
def test_unsafe_private_key_metadata_is_not_read(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    unsafe_kind: str,
) -> None:
    pki = _workspace(tmp_path, leaf_keys=False, backup=False)
    service_key = pki / "services/app/private/tls.key"
    service_key.parent.mkdir(mode=0o700, parents=True)
    outside = tmp_path / "outside.key"
    _private_key(outside, encrypted=False, secret=SERVICE_SECRET)
    if unsafe_kind == "symlink":
        service_key.symlink_to(outside)
    elif unsafe_kind == "hardlink":
        os.link(outside, service_key)
    else:
        _private_key(service_key, encrypted=False, secret=SERVICE_SECRET)
        service_key.chmod(0o644)

    result = _run(process_runner, pki, "--format", "json")
    assert result.status == 2
    report = json.loads(result.stdout)
    assert "unsafe-private-key" in _finding_codes(report)
    assert _material(report, "service:app")["encryption_evidence"] == "unknown"
    assert SERVICE_SECRET not in result.stdout + result.stderr


def test_first_line_reader_rejects_same_inode_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "key"
    path.write_bytes(b"-----BEGIN ENCRYPTED PRIVATE KEY-----\nsecret-tail")
    path.chmod(0o600)
    writer = os.open(path, os.O_WRONLY | os.O_CLOEXEC)
    real_pread = os.pread

    def mutate(fd: int, size: int, offset: int) -> bytes:
        data = real_pread(fd, size, offset)
        os.pwrite(writer, b"X", 0)
        return data

    try:
        monkeypatch.setattr(filesystem.os, "pread", mutate)
        with OpenedFile(path, policy=FilePolicy(mode=0o600, links=1)) as opened:
            with pytest.raises(ApplicationError, match="private key changed while reading"):
                custody_report._classify_first_line(opened, "key", "private key")
    finally:
        os.close(writer)


def test_descendant_open_rejects_ancestry_mutation(tmp_path: Path) -> None:
    pki = tmp_path / "pki"
    private = pki / "authority/private"
    private.mkdir(mode=0o700, parents=True)
    for directory in (pki, pki / "authority", private):
        directory.chmod(0o700)
    key = private / "key"
    key.write_bytes(b"key")
    key.chmod(0o600)

    with OpenedDirectory(pki, policy=DirectoryPolicy(mode=0o700)) as root:
        opened = open_descendant_file(
            root,
            ("authority", "private", "key"),
            directory_policy=DirectoryPolicy(mode=0o700),
            file_policy=FilePolicy(mode=0o600, links=1),
        )
        try:
            original = pki / "authority.original"
            os.rename(pki / "authority", original)
            (pki / "authority").mkdir(mode=0o700)
            with pytest.raises(FilesystemIdentityError):
                opened.recheck()
        finally:
            opened.close()


def test_unexpected_key_is_counted_without_printing_its_path_or_content(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
    pki = _workspace(tmp_path, leaf_keys=False, backup=False)
    unexpected = pki / "legacy/private copy with hostname.key"
    _private_key(unexpected, encrypted=False, secret=SERVICE_SECRET)

    result = _run(process_runner, pki, "--format", "json")
    report = json.loads(result.stdout)
    assert result.status == 2
    assert any(code.startswith("unexpected-private-key-count:") for code in _finding_codes(report))
    assert "private copy with hostname.key" not in result.stdout
    assert SERVICE_SECRET not in result.stdout + result.stderr


def test_invalid_age_header_is_reported(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
    pki = _workspace(tmp_path, leaf_keys=False)
    backup = pki / "backups/platform-pki-20260805-120000.tar.gz.age"
    _write(backup, "not-an-age-envelope\nsecret-archive-payload\n")

    result = _run(process_runner, pki, "--format", "json")
    report = json.loads(result.stdout)
    assert result.status == 2
    assert "invalid-age-backup" in _finding_codes(report)
    assert _material(report, "backup:20260805-120000:age")["encryption_evidence"] == "unknown"
    assert "secret-archive-payload" not in result.stdout + result.stderr


def test_overlong_age_header_is_bounded_and_reported(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
    pki = _workspace(tmp_path, leaf_keys=False)
    backup = pki / "backups/platform-pki-20260805-120000.tar.gz.age"
    _write(backup, f"{'A' * 4096}\nsecret-archive-payload\n")

    result = _run(process_runner, pki, "--format", "json")
    report = json.loads(result.stdout)
    assert result.status == 2
    assert "oversized-backup-header" in _finding_codes(report)
    assert _material(report, "backup:20260805-120000:age")["encryption_evidence"] == "overlong-header"
    assert "secret-archive-payload" not in result.stdout + result.stderr


def test_nul_heavy_age_header_is_byte_bounded_and_reported(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
    pki = _workspace(tmp_path, leaf_keys=False)
    backup = pki / "backups/platform-pki-20260805-120000.tar.gz.age"
    backup.write_bytes(b"\x00" * 10000 + b"secret-archive-payload")
    backup.chmod(0o600)

    result = _run(process_runner, pki, "--format", "json")
    report = json.loads(result.stdout)
    assert result.status == 2
    assert "binary-backup-header" in _finding_codes(report)
    assert _material(report, "backup:20260805-120000:age")["encryption_evidence"] == "nul-header"
    assert "secret-archive-payload" not in result.stdout + result.stderr


def test_missing_backup_receipt_is_reported(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
    pki = _workspace(tmp_path, leaf_keys=False)
    (pki / "backups/platform-pki-20260805-120000.tar.gz.age.receipt").unlink()

    result = _run(process_runner, pki, "--format", "json")
    report = json.loads(result.stdout)
    assert result.status == 2
    assert "missing-backup-receipt" in _finding_codes(report)


def test_malformed_backup_receipt_is_reported(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
    pki = _workspace(tmp_path, leaf_keys=False)
    receipt = pki / "backups/platform-pki-20260805-120000.tar.gz.age.receipt"
    _write(receipt, "schema=2\nbackup_path=/wrong/archive\n")

    result = _run(process_runner, pki, "--format", "json")
    report = json.loads(result.stdout)
    assert result.status == 2
    assert "invalid-backup-receipt" in _finding_codes(report)


@pytest.mark.parametrize("control", (b"\r", b"\t", b"\x7f"))
def test_receipt_parser_rejects_controls_and_del(tmp_path: Path, control: bytes) -> None:
    pki = _workspace(tmp_path, leaf_keys=False)
    receipt = Path(f"{pki}/backups/platform-pki-20260805-120000.tar.gz.age.receipt")
    data = receipt.read_bytes().replace(b"schema=2", b"schema=2" + control, 1)
    assert custody_report._parse_receipt(data) is None


def test_oversized_backup_receipt_is_rejected_before_parsing(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
    pki = _workspace(tmp_path, leaf_keys=False)
    receipt = pki / "backups/platform-pki-20260805-120000.tar.gz.age.receipt"
    _write(receipt, f"schema=2\n{'A' * 70000}\nreceipt-secret-payload\n")

    result = _run(process_runner, pki, "--format", "json")
    report = json.loads(result.stdout)
    assert result.status == 2
    assert "invalid-backup-receipt" in _finding_codes(report)
    assert "receipt-secret-payload" not in result.stdout + result.stderr


def test_receipt_same_inode_mutation_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pki = _workspace(tmp_path, leaf_keys=False)
    archive = pki / "backups/platform-pki-20260805-120000.tar.gz.age"
    receipt = Path(f"{archive}.receipt")
    writer = os.open(receipt, os.O_WRONLY | os.O_CLOEXEC)
    real_pread = os.pread
    mutated = False

    def mutate(fd: int, size: int, offset: int) -> bytes:
        nonlocal mutated
        data = real_pread(fd, size, offset)
        if not mutated:
            mutated = True
            os.pwrite(writer, b"X", 0)
        return data

    try:
        monkeypatch.setattr(filesystem.os, "pread", mutate)
        with OpenedDirectory(pki, policy=DirectoryPolicy(mode=0o700)) as root:
            report = custody_report.Report(os.fspath(pki), root)
            with OpenedFile(archive) as opened:
                with pytest.raises(ApplicationError, match="backup receipt changed while reading"):
                    custody_report._receipt_matches_archive(
                        report,
                        ("backups", receipt.name),
                        ("backups", archive.name),
                        opened.identity,
                    )
    finally:
        os.close(writer)


def _resize_receipt(receipt: Path, size: int) -> None:
    lines = receipt.read_bytes().splitlines()
    index = next(index for index, line in enumerate(lines) if line.startswith(b"created_epoch="))
    lines[index] = b"created_epoch="
    base = b"\n".join(lines) + b"\n"
    assert len(base) < size
    lines[index] += b"1" * (size - len(base))
    data = b"\n".join(lines) + b"\n"
    assert len(data) == size
    receipt.write_bytes(data)
    receipt.chmod(0o600)


@pytest.mark.parametrize("command", PYTHON_INTERFACES)
@pytest.mark.parametrize(("size", "valid"), ((65536, True), (65537, False)))
def test_receipt_exact_size_boundaries_match_frozen_oracle(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    command: tuple[Path | str, ...],
    size: int,
    valid: bool,
) -> None:
    pki = _workspace(tmp_path, leaf_keys=False)
    archive = pki / "backups/platform-pki-20260805-120000.tar.gz.age"
    _resize_receipt(Path(f"{archive}.receipt"), size)
    oracle = _run_interface(process_runner, (ORACLE,), pki, "--format", "json")
    result = _run_interface(process_runner, command, pki, "--format", "json")
    assert (result.status, result.stdout, result.stderr) == (
        oracle.status,
        oracle.stdout,
        oracle.stderr,
    )
    assert ("invalid-backup-receipt" not in result.stdout) is valid


@pytest.mark.parametrize("command", PYTHON_INTERFACES)
def test_unordered_receipt_without_final_newline_matches_frozen_oracle(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    command: tuple[Path | str, ...],
) -> None:
    pki = _workspace(tmp_path, leaf_keys=False)
    receipt = Path(f"{pki}/backups/platform-pki-20260805-120000.tar.gz.age.receipt")
    receipt.write_bytes(b"\n".join(reversed(receipt.read_bytes().splitlines())))
    receipt.chmod(0o600)
    oracle = _run_interface(process_runner, (ORACLE,), pki, "--format", "json")
    result = _run_interface(process_runner, command, pki, "--format", "json")
    assert (result.status, result.stdout, result.stderr) == (
        oracle.status,
        oracle.stdout,
        oracle.stderr,
    )
    assert result.status == 0


@pytest.mark.parametrize("command", PYTHON_INTERFACES)
def test_receipt_archive_digest_is_recorded_but_not_recalculated(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    command: tuple[Path | str, ...],
) -> None:
    pki = _workspace(tmp_path, leaf_keys=False)
    archive = pki / "backups/platform-pki-20260805-120000.tar.gz.age"
    receipt = Path(f"{archive}.receipt")
    recorded = b"f" * 64
    assert sha256(archive.read_bytes()).hexdigest().encode() != recorded
    receipt.write_bytes(
        receipt.read_bytes().replace(b"archive_sha256=" + b"0" * 64, b"archive_sha256=" + recorded)
    )
    receipt.chmod(0o600)

    oracle = _run_interface(process_runner, (ORACLE,), pki, "--format", "json")
    result = _run_interface(process_runner, command, pki, "--format", "json")
    assert (result.status, result.stdout, result.stderr) == (
        oracle.status,
        oracle.stdout,
        oracle.stderr,
    )
    assert result.status == 0


def test_historical_legacy_backup_receipt_is_valid_in_generation_layout(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
    pki = _workspace(tmp_path, leaf_keys=False)
    archive = pki / "backups/platform-pki-20260805-120000.tar.gz.age"
    _receipt(archive, layout="legacy")

    result = _run(process_runner, pki, "--format", "json")
    report = json.loads(result.stdout)
    assert result.status == 0
    assert report["findings"] == []


def test_hidden_backup_and_visible_and_hidden_orphan_receipts_are_reported(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
    pki = _workspace(tmp_path, leaf_keys=False, backup=False)
    _write(pki / "backups/.hidden-plaintext.tar.gz", "plaintext-secret-archive\n")
    _write(pki / "backups/orphan.receipt", "orphan\n")
    _write(pki / "backups/.hidden-orphan.receipt", "orphan\n")

    result = _run(process_runner, pki, "--format", "json")
    report = json.loads(result.stdout)
    assert result.status == 2
    codes = _finding_codes(report)
    assert "plaintext-backup" in codes
    assert "orphan-backup-receipt-count:2" in codes
    assert "plaintext-secret-archive" not in result.stdout + result.stderr


def test_plain_and_age_backups_with_same_timestamp_have_distinct_ids(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
    pki = _workspace(tmp_path, leaf_keys=False)
    plain = pki / "backups/platform-pki-20260805-120000.tar.gz"
    _write(plain, "plaintext-secret-archive\n")
    _receipt(plain)

    result = _run(process_runner, pki, "--format", "json")
    report = json.loads(result.stdout)
    materials = report["materials"]
    ids = [material["id"] for material in materials]
    assert result.status == 2
    assert "backup:20260805-120000:age" in ids
    assert "backup:20260805-120000:plain" in ids
    assert len(ids) == len(set(ids))
    assert "plaintext-secret-archive" not in result.stdout + result.stderr


def test_non_luks_ancestry_is_evidence_not_unencrypted_finding(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
    pki = _workspace(tmp_path, leaf_keys=False, backup=False)
    executable_root = ROOT / ".tmp"
    executable_root.mkdir(mode=0o700, exist_ok=True)
    fake_bin = Path(tempfile.mkdtemp(prefix="custody-storage.", dir=executable_root))
    try:
        _write(fake_bin / "findmnt", "#!/bin/sh\nprintf '%s\\n' /dev/fake\n", mode=0o700)
        _write(fake_bin / "lsblk", "#!/bin/sh\nprintf '%s\\n' ext4\n", mode=0o700)
        environment = os.environ.copy()
        environment["PATH"] = f"{fake_bin}:{environment['PATH']}"
        result = process_runner(
            [*TOOL, "--pki-dir", pki, "--format", "json"],
            env=environment,
            timeout=30,
        )
    finally:
        shutil.rmtree(fake_bin)
    report = json.loads(result.stdout)
    assert result.status == 0
    assert report["storage_encryption_evidence"] == "no-luks-ancestor"
    assert report["findings"] == []


def test_empty_storage_ancestry_is_unknown(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
    pki = _workspace(tmp_path, leaf_keys=False, backup=False)
    executable_root = ROOT / ".tmp"
    executable_root.mkdir(mode=0o700, exist_ok=True)
    fake_bin = Path(tempfile.mkdtemp(prefix="custody-empty-storage.", dir=executable_root))
    try:
        _write(fake_bin / "findmnt", "#!/bin/sh\nprintf '%s\\n' /dev/fake\n", mode=0o700)
        _write(fake_bin / "lsblk", "#!/bin/sh\nexit 0\n", mode=0o700)
        environment = os.environ.copy()
        environment["PATH"] = f"{fake_bin}:{environment['PATH']}"
        result = process_runner(
            [*TOOL, "--pki-dir", pki, "--format", "json"],
            env=environment,
            timeout=30,
        )
    finally:
        shutil.rmtree(fake_bin)
    report = json.loads(result.stdout)
    assert result.status == 0
    assert report["storage_encryption_evidence"] == "unknown"


@pytest.mark.parametrize("command", PYTHON_INTERFACES)
def test_storage_helper_argv_order_and_evidence_match_frozen_oracle(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    command: tuple[Path | str, ...],
) -> None:
    pki = _workspace(tmp_path, leaf_keys=False, backup=False)
    fake_bin = tmp_path / "storage-bin"
    fake_bin.mkdir(mode=0o700)
    log = tmp_path / "storage-argv"
    _write(
        fake_bin / "findmnt",
        "#!/bin/sh\nprintf 'findmnt <%s> <%s> <%s> <%s> <%s>\\n' \"$1\" \"$2\" \"$3\" \"$4\" \"$5\" >>\"$STORAGE_LOG\"\nprintf '%s\\n' /dev/fake\n",
        mode=0o700,
    )
    _write(
        fake_bin / "lsblk",
        "#!/bin/sh\nprintf 'lsblk <%s> <%s> <%s> <%s> <%s>\\n' \"$1\" \"$2\" \"$3\" \"$4\" \"$5\" >>\"$STORAGE_LOG\"\nprintf '%s\\n' crypto_LUKS\n",
        mode=0o700,
    )
    environment = {
        **os.environ,
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "STORAGE_LOG": os.fspath(log),
    }
    oracle = _run_interface(
        process_runner, (ORACLE,), pki, "--format", "json", env=environment
    )
    result = _run_interface(
        process_runner, command, pki, "--format", "json", env=environment
    )
    assert (result.status, result.stdout, result.stderr) == (
        oracle.status,
        oracle.stdout,
        oracle.stderr,
    )
    expected = (
        f"findmnt <--noheadings> <--output> <SOURCE> <--target> <{pki}>\n"
        "lsblk <--inverse> <--noheadings> <--output> <FSTYPE> </dev/fake>\n"
    )
    assert log.read_text(encoding="utf-8") == expected * 2


@pytest.mark.parametrize("command", PYTHON_INTERFACES)
@pytest.mark.parametrize(
    ("findmnt_output", "lsblk_output", "expected_source", "expected_evidence"),
    (
        ("/dev/fake[/subvolume]\n\n", "\ncrypto_LUKS\n", "/dev/fake", "luks-ancestor"),
        (" /dev/fake [bind]\n\n", " crypto_LUKS \n\n", " /dev/fake ", "no-luks-ancestor"),
        ("/dev/fake\n", "\n\n", "/dev/fake", "unknown"),
    ),
    ids=("bracket-and-blank-line", "significant-spaces", "blank-ancestry"),
)
def test_storage_helper_whitespace_matches_frozen_oracle(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    command: tuple[Path | str, ...],
    findmnt_output: str,
    lsblk_output: str,
    expected_source: str,
    expected_evidence: str,
) -> None:
    pki = _workspace(tmp_path, leaf_keys=False, backup=False)
    fake_bin = tmp_path / "storage-whitespace-bin"
    fake_bin.mkdir(mode=0o700)
    log = tmp_path / "storage-source"
    _write(fake_bin / "findmnt", "#!/bin/sh\nprintf '%s' \"$FINDMNT_OUTPUT\"\n", mode=0o700)
    _write(
        fake_bin / "lsblk",
        "#!/bin/sh\nprintf '<%s>\\n' \"$5\" >>\"$STORAGE_LOG\"\nprintf '%s' \"$LSBLK_OUTPUT\"\n",
        mode=0o700,
    )
    environment = {
        **os.environ,
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "STORAGE_LOG": os.fspath(log),
        "FINDMNT_OUTPUT": findmnt_output,
        "LSBLK_OUTPUT": lsblk_output,
    }

    oracle = _run_interface(
        process_runner, (ORACLE,), pki, "--format", "json", env=environment
    )
    result = _run_interface(
        process_runner, command, pki, "--format", "json", env=environment
    )
    assert (result.status, result.stdout, result.stderr) == (
        oracle.status,
        oracle.stdout,
        oracle.stderr,
    )
    assert json.loads(result.stdout)["storage_encryption_evidence"] == expected_evidence
    assert log.read_text(encoding="utf-8") == f"<{expected_source}>\n" * 2


@pytest.mark.parametrize("failure", (ProcessOutputOverflowError, ProcessTimeoutError))
def test_storage_helper_limits_degrade_to_unknown_without_diagnostics(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: Any,
) -> None:
    monkeypatch.setattr(custody_report.shutil, "which", lambda *_args, **_kwargs: "/tool")

    def fail(*_args: object, **_kwargs: object) -> None:
        raise failure()

    monkeypatch.setattr(custody_report, "run_process", fail)
    assert custody_report._detect_storage_encryption(os.fspath(tmp_path), os.environ) == "unknown"


def test_unsafe_managed_directory_is_reported_without_exposing_path(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
    pki = _workspace(tmp_path, leaf_keys=False, backup=False)
    unsafe = pki / "private directory with hostname"
    unsafe.mkdir(mode=0o755)

    result = _run(process_runner, pki, "--format", "json")
    report = json.loads(result.stdout)
    assert result.status == 2
    assert any(code.startswith("unsafe-managed-path-count:") for code in _finding_codes(report))
    assert "private directory with hostname" not in result.stdout


@pytest.mark.parametrize("command", PYTHON_INTERFACES)
@pytest.mark.parametrize("scenario", ("mixed", "recovery"))
def test_invalid_and_recovery_failures_match_frozen_oracle(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    command: tuple[Path | str, ...],
    scenario: str,
) -> None:
    pki = _workspace(tmp_path, leaf_keys=False, backup=False)
    if scenario == "mixed":
        (pki / "root-ca").mkdir(mode=0o700)
    else:
        _write(pki / "state/csr/finalization-recovery-journal", "operation=csr-finalize\n")
        _write(pki / "state/csr/recovery-journal", "operation=csr-sign\n")
        _write(pki / "state/rollover/recovery-required", "required\n")
    oracle = _run_interface(process_runner, (ORACLE,), pki, "--format", "json")
    result = _run_interface(process_runner, command, pki, "--format", "json")
    assert (result.status, result.stdout, result.stderr) == (
        oracle.status,
        oracle.stdout,
        oracle.stderr,
    )
    assert result.status == 1


@pytest.mark.parametrize("command", PYTHON_INTERFACES)
def test_lifecycle_lock_contention_matches_frozen_oracle(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    command: tuple[Path | str, ...],
) -> None:
    pki = _workspace(tmp_path, leaf_keys=False, backup=False)
    lock = pki / "locks/lifecycle"
    lock.touch(mode=0o600)
    lock.chmod(0o600)
    descriptor = os.open(lock, os.O_RDWR | os.O_CLOEXEC)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        oracle = _run_interface(process_runner, (ORACLE,), pki, "--format", "json")
        result = _run_interface(process_runner, command, pki, "--format", "json")
    finally:
        os.close(descriptor)
    assert (result.status, result.stdout, result.stderr) == (
        oracle.status,
        oracle.stdout,
        oracle.stderr,
    )


def test_incomplete_traversal_fails_instead_of_returning_partial_report(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
    pki = _workspace(tmp_path, leaf_keys=False, backup=False)
    unreadable = pki / "private-hostname-must-not-appear"
    unreadable.mkdir(mode=0o700)
    unreadable.chmod(0)
    try:
        result = _run(process_runner, pki, "--format", "json")
    finally:
        unreadable.chmod(0o700)
    assert result.status == 1
    assert result.stdout == ""
    assert "Cannot enumerate complete managed PKI metadata" in result.stderr
    assert "private-hostname-must-not-appear" not in result.stderr


@pytest.mark.parametrize("command", PYTHON_INTERFACES)
def test_incomplete_traversal_matches_frozen_oracle_without_path_disclosure(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    command: tuple[Path | str, ...],
) -> None:
    pki = _workspace(tmp_path, leaf_keys=False, backup=False)
    unreadable = pki / "private-hostname-must-not-appear"
    unreadable.mkdir(mode=0o700)
    unreadable.chmod(0)
    try:
        oracle = _run_interface(process_runner, (ORACLE,), pki, "--format", "json")
        result = _run_interface(process_runner, command, pki, "--format", "json")
    finally:
        unreadable.chmod(0o700)
    assert (result.status, result.stdout, result.stderr) == (
        oracle.status,
        oracle.stdout,
        oracle.stderr,
    )
    assert "private-hostname-must-not-appear" not in result.stderr


def test_metadata_walker_rejects_entry_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root_path = tmp_path / "tree"
    root_path.mkdir(mode=0o700)
    entry = root_path / "entry"
    entry.write_bytes(b"content")
    replacement = root_path / "replacement"
    replacement.write_bytes(b"replacement")
    real_stat = filesystem.os.stat
    calls = 0

    def replacing_stat(path: Any, *args: Any, **kwargs: Any) -> os.stat_result:
        nonlocal calls
        result = real_stat(path, *args, **kwargs)
        if path == "entry":
            calls += 1
            if calls == 1:
                os.replace(replacement, entry)
        return result

    monkeypatch.setattr(filesystem.os, "stat", replacing_stat)
    with OpenedDirectory(root_path) as root:
        with pytest.raises(FilesystemTraversalError):
            tuple(walk_metadata(root))


def test_report_creates_no_sensitive_path_list_temp_files(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
    pki = _workspace(tmp_path, leaf_keys=False, backup=False)
    temporary = tmp_path / "temporary"
    temporary.mkdir(mode=0o700)
    environment = {**os.environ, "TMPDIR": os.fspath(temporary)}
    before = tuple(temporary.iterdir())
    result = process_runner(
        [*TOOL, "--pki-dir", pki, "--format", "json"], env=environment, timeout=30
    )
    assert result.status == 0
    assert tuple(temporary.iterdir()) == before


def test_legacy_layout_is_classified_without_requiring_migration(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
    pki = _legacy_workspace(tmp_path)

    result = _run(process_runner, pki, "--format", "json")
    report = json.loads(result.stdout)
    assert result.status == 0
    assert report["layout"] == "legacy"
    assert _material(report, "legacy-root")["encryption_evidence"] == "encrypted-pkcs8-header"
    assert _material(report, "legacy-intermediate")["encryption_evidence"] == "encrypted-pkcs8-header"


@pytest.mark.parametrize("command", PYTHON_INTERFACES)
@pytest.mark.parametrize("report_format", ("text", "json"))
def test_clean_legacy_reports_match_frozen_oracle_bytes(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    command: tuple[Path | str, ...],
    report_format: str,
) -> None:
    pki = _legacy_workspace(tmp_path)
    oracle = _run_interface(process_runner, (ORACLE,), pki, "--format", report_format)
    result = _run_interface(process_runner, command, pki, "--format", report_format)
    assert (result.status, result.stdout, result.stderr) == (
        oracle.status,
        oracle.stdout,
        oracle.stderr,
    )


def test_report_preserves_sensitive_files(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
    pki = _workspace(tmp_path)
    before = _sensitive_snapshot(pki)
    result = _run(process_runner, pki, "--format", "json")
    after = _sensitive_snapshot(pki)
    assert result.status == 2
    assert after == before
