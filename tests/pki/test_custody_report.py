from __future__ import annotations

import json
import os
import shutil
import tempfile
from collections.abc import Callable
from hashlib import sha256
from pathlib import Path

import pytest

from ..harness import ProcessResult


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "bin/platform-pki-custody-report"
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


def _run(
    process_runner: Callable[..., ProcessResult],
    pki: Path,
    *arguments: str,
) -> ProcessResult:
    return process_runner([TOOL, "--pki-dir", pki, *arguments], timeout=30)


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
    help_result = process_runner([TOOL, "--help"])
    assert help_result.status == 0
    assert "only the first PEM header line" in help_result.stdout
    assert help_result.stderr == ""

    version_result = process_runner([TOOL, "--version"])
    assert version_result.status == 0
    assert version_result.stdout == f"platform-pki-custody-report {VERSION}\n"
    assert version_result.stderr == ""


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


@pytest.mark.parametrize(
    ("target_kind", "expected_error"),
    (
        ("key", "private key identity changed while opening"),
        ("backup", "age backup identity changed while opening"),
        ("receipt", "backup receipt identity changed while opening"),
    ),
)
def test_descriptor_bound_reads_reject_path_replacement(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    target_kind: str,
    expected_error: str,
) -> None:
    pki = _workspace(tmp_path, leaf_keys=False)
    archive = pki / "backups/platform-pki-20260805-120000.tar.gz.age"
    targets = {
        "key": pki / "authorities/roots/g1/private/root-ca.key",
        "backup": archive,
        "receipt": Path(f"{archive}.receipt"),
    }
    target = targets[target_kind]
    replacement = tmp_path / f"replacement-{target_kind}"
    _write(replacement, "replacement-content-must-not-appear\n")
    fake_library = tmp_path / "fake-lib/platform-pki-common.sh"
    _write(
        fake_library,
        """# shellcheck source=../../../lib/platform-pki-common.sh
source "$REAL_COMMON"
pki_file_identity() {
  local path=$1
  if [[ $path == "$SWAP_TARGET" ]]; then
    if [[ ! -e $SWAP_SEEN ]]; then
      touch "$SWAP_SEEN"
    elif [[ ! -e $SWAP_DONE ]]; then
      mv -- "$SWAP_TARGET" "$SWAP_TARGET.original"
      cp -- "$SWAP_REPLACEMENT" "$SWAP_TARGET"
      chmod 600 "$SWAP_TARGET"
      touch "$SWAP_DONE"
    fi
  fi
  stat -c '%d:%i:%u:%a:%h:%s:%y:%z:%F' -- "$path"
}
""",
    )
    environment = os.environ.copy()
    environment.update(
        {
            "SWAP_TARGET": os.fspath(target),
            "SWAP_REPLACEMENT": os.fspath(replacement),
            "SWAP_SEEN": os.fspath(tmp_path / "swap-seen"),
            "SWAP_DONE": os.fspath(tmp_path / "swap-done"),
            "REAL_COMMON": os.fspath(ROOT / "lib/platform-pki-common.sh"),
            "PLATFORM_TOOLS_LIB_DIR": os.fspath(fake_library.parent),
        }
    )

    result = process_runner(
        [TOOL, "--pki-dir", pki, "--format", "json"],
        env=environment,
        timeout=30,
    )
    assert result.status == 1
    assert result.stdout == ""
    assert expected_error in result.stderr
    assert "replacement-content-must-not-appear" not in result.stderr


def test_archive_replacement_after_header_invalidates_receipt_binding(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
    pki = _workspace(tmp_path, leaf_keys=False)
    archive = pki / "backups/platform-pki-20260805-120000.tar.gz.age"
    replacement = tmp_path / "replacement-archive"
    _write(replacement, "age-encryption.org/v1\nreplacement-payload-must-not-appear\n")
    fake_library = tmp_path / "fake-lib/platform-pki-common.sh"
    _write(
        fake_library,
        """# shellcheck source=../../../lib/platform-pki-common.sh
source "$REAL_COMMON"
pki_file_identity() {
  local path=$1 count=0
  if [[ $path == "$SWAP_TARGET" ]]; then
    [[ ! -f $SWAP_COUNT ]] || IFS= read -r count <"$SWAP_COUNT"
    count=$((count + 1))
    printf '%s\n' "$count" >"$SWAP_COUNT"
    if (( count == 4 )); then
      mv -- "$SWAP_TARGET" "$SWAP_TARGET.original"
      cp -- "$SWAP_REPLACEMENT" "$SWAP_TARGET"
      chmod 600 "$SWAP_TARGET"
    fi
  fi
  stat -c '%d:%i:%u:%a:%h:%s:%y:%z:%F' -- "$path"
}
""",
    )
    environment = os.environ.copy()
    environment.update(
        {
            "SWAP_TARGET": os.fspath(archive),
            "SWAP_REPLACEMENT": os.fspath(replacement),
            "SWAP_COUNT": os.fspath(tmp_path / "swap-count"),
            "REAL_COMMON": os.fspath(ROOT / "lib/platform-pki-common.sh"),
            "PLATFORM_TOOLS_LIB_DIR": os.fspath(fake_library.parent),
        }
    )

    result = process_runner(
        [TOOL, "--pki-dir", pki, "--format", "json"],
        env=environment,
        timeout=30,
    )
    report = json.loads(result.stdout)
    assert result.status == 2
    assert "invalid-backup-receipt" in _finding_codes(report)
    assert "replacement-payload-must-not-appear" not in result.stdout + result.stderr


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
            [TOOL, "--pki-dir", pki, "--format", "json"],
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
            [TOOL, "--pki-dir", pki, "--format", "json"],
            env=environment,
            timeout=30,
        )
    finally:
        shutil.rmtree(fake_bin)
    report = json.loads(result.stdout)
    assert result.status == 0
    assert report["storage_encryption_evidence"] == "unknown"


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


def test_failed_key_traversal_suppresses_private_path_diagnostic(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
    pki = _workspace(tmp_path, leaf_keys=False, backup=False)
    executable_root = ROOT / ".tmp"
    executable_root.mkdir(mode=0o700, exist_ok=True)
    fake_bin = Path(tempfile.mkdtemp(prefix="custody-find.", dir=executable_root))
    try:
        fake_find = fake_bin / "find"
        _write(
            fake_find,
            """#!/bin/sh
if [ ! -e "$FIND_CALLED" ]; then
  : >"$FIND_CALLED"
  exec "$REAL_FIND" "$@"
fi
printf '%s\n' 'private-key-path-must-not-appear' >&2
exit 1
""",
            mode=0o700,
        )
        real_find = shutil.which("find")
        assert real_find is not None
        environment = os.environ.copy()
        environment.update(
            {
                "PATH": f"{fake_bin}:{environment['PATH']}",
                "FIND_CALLED": os.fspath(tmp_path / "find-called"),
                "REAL_FIND": real_find,
            }
        )
        result = process_runner(
            [TOOL, "--pki-dir", pki, "--format", "json"],
            env=environment,
            timeout=30,
        )
    finally:
        shutil.rmtree(fake_bin)
    assert result.status == 1
    assert result.stdout == ""
    assert "Cannot enumerate complete managed private-key paths" in result.stderr
    assert "private-key-path-must-not-appear" not in result.stderr


def test_legacy_layout_is_classified_without_requiring_migration(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
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

    result = _run(process_runner, pki, "--format", "json")
    report = json.loads(result.stdout)
    assert result.status == 0
    assert report["layout"] == "legacy"
    assert _material(report, "legacy-root")["encryption_evidence"] == "encrypted-pkcs8-header"
    assert _material(report, "legacy-intermediate")["encryption_evidence"] == "encrypted-pkcs8-header"


def test_report_preserves_sensitive_files(
    tmp_path: Path, process_runner: Callable[..., ProcessResult]
) -> None:
    pki = _workspace(tmp_path)
    before = _sensitive_snapshot(pki)
    result = _run(process_runner, pki, "--format", "json")
    after = _sensitive_snapshot(pki)
    assert result.status == 2
    assert after == before
