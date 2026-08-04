from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from pathlib import Path

import pytest

from ..harness import ProcessResult
from .support import BIN, assert_result, mode, write_private


pytestmark = pytest.mark.pki
TOOL = BIN / "platform-pki-backup"


def create_pki_tree(pki: Path) -> None:
    for directory in (
        pki / "inventory",
        pki / "root-ca/private",
        pki / "intermediate-ca",
        pki / "export/ansible",
    ):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    for directory in (pki, *pki.rglob("*")):
        if directory.is_dir():
            directory.chmod(0o700)
    write_private(
        pki / "inventory/services.yml",
        "services:\n  backup-test:\n    common_name: backup.example.internal\n"
        "    dns:\n      - backup.example.internal\n",
    )
    write_private(pki / "root-ca/private/root-ca.key", "root key placeholder\n")
    write_private(pki / "export/ansible/README.txt", "export placeholder\n")


def backup(process_runner: Callable[..., ProcessResult], env: Mapping[str, str], pki: Path, destination: Path | None = None) -> ProcessResult:
    arguments: list[object] = [TOOL, "--pki-dir", pki]
    if destination is not None:
        arguments.extend(("--backup-dir", destination))
    arguments.append("--allow-plain-backup")
    return process_runner(arguments, env=env, timeout=30)


def archive_entries(process_runner, env, archive: Path) -> set[str]:
    result = process_runner(["tar", "-tzf", archive], env=env, timeout=10)
    assert_result(result, 0, stderr="")
    return set(result.stdout.splitlines())


def latest(directory: Path) -> Path:
    archives = sorted(directory.glob("platform-pki-*.tar.gz"))
    assert archives
    return archives[-1]


@pytest.mark.parametrize(
    ("case", "relative_backup", "repeat"),
    [
        ("default", "backups", True),
        ("custom", "custom-backups", False),
        ("pattern", "backups[1]", False),
        ("path with spaces", "backups", False),
    ],
)
def test_backup_excludes_in_tree_backup_directory(tmp_path, process_runner, isolated_environment, case, relative_backup, repeat) -> None:
    pki = tmp_path / case / "pki"
    destination = pki / relative_backup
    create_pki_tree(pki)
    explicit = destination if relative_backup != "backups" else None
    assert_result(backup(process_runner, isolated_environment, pki, explicit), 0)
    if repeat:
        assert_result(backup(process_runner, isolated_environment, pki, explicit), 0)
    entries = archive_entries(process_runner, isolated_environment, latest(destination))
    assert "pki/inventory/services.yml" in entries
    prefix = f"pki/{relative_backup}"
    assert all(entry != prefix and not entry.startswith(prefix + "/") for entry in entries)


def test_backup_rejects_symlink_pki_directory(tmp_path, process_runner, isolated_environment) -> None:
    real = tmp_path / "real/pki"
    alias = tmp_path / "pki-alias"
    create_pki_tree(real)
    alias.symlink_to(real, target_is_directory=True)
    result = backup(process_runner, isolated_environment, alias)
    assert result.status == 1
    assert "non-symlink directory" in result.stderr


def test_backup_resolves_symlink_backup_directory_for_exclusion(tmp_path, process_runner, isolated_environment) -> None:
    pki = tmp_path / "pki"
    real = pki / "real-backups"
    alias = pki / "backup-link"
    create_pki_tree(pki)
    real.mkdir(mode=0o700)
    alias.symlink_to(real, target_is_directory=True)
    assert_result(backup(process_runner, isolated_environment, pki, alias), 0)
    archive = latest(real)
    assert mode(archive) == 0o600
    entries = archive_entries(process_runner, isolated_environment, archive)
    assert "pki/inventory/services.yml" in entries
    for prefix in ("pki/real-backups", "pki/backup-link"):
        assert all(entry != prefix and not entry.startswith(prefix + "/") for entry in entries)


def test_backup_rejects_pki_as_backup_directory(tmp_path, process_runner, isolated_environment) -> None:
    pki = tmp_path / "pki"
    create_pki_tree(pki)
    result = backup(process_runner, isolated_environment, pki, pki)
    assert result.status == 1
    assert "Backup directory cannot be the PKI directory itself" in result.stderr
