import os
import stat
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "bin/platform-config-init"
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()


@pytest.mark.parametrize(
    ("arguments", "status", "stdout_text", "stderr_text"),
    [
        (["--help"], 0, "Usage:", ""),
        (["--version"], 0, f"platform-config-init {VERSION}\n", ""),
        (["--unknown"], 1, "", "invalid option: --unknown"),
        (["--config-dir"], 1, "", "--config-dir requires an argument"),
        (
            ["--config-dir", ""],
            1,
            "",
            "validation error in --config-dir PATH:\nmust not be empty",
        ),
        (["--config-dir="], 1, "", "invalid option: --config-dir="),
    ],
    ids=["help", "version", "unknown-option", "missing-path", "empty-path", "equals-empty"],
)
def test_parser_contract(
    arguments: list[str],
    status: int,
    stdout_text: str,
    stderr_text: str,
    process_runner,
) -> None:
    result = process_runner([TOOL, *arguments])

    assert result.status == status
    if arguments == ["--help"]:
        assert stdout_text in result.stdout
        assert "platform-config-init --version | -v" in result.stdout
    else:
        assert result.stdout == stdout_text
    if stderr_text:
        assert stderr_text in result.stderr
    else:
        assert result.stderr == ""


def test_help_after_option_is_rejected_without_execution(
    tmp_path: Path, process_runner
) -> None:
    destination = tmp_path / "help-order"
    result = process_runner([TOOL, "--config-dir", destination, "--help"])

    assert result.status == 1
    assert result.stdout == ""
    assert "invalid option: --help" in result.stderr
    assert not destination.exists()


def test_custom_namespace_is_created_with_private_modes(
    tmp_path: Path, process_runner
) -> None:
    destination = tmp_path / "custom namespace"
    result = process_runner([TOOL, f"--config-dir={destination}"])

    assert result.status == 0
    assert result.stderr == ""
    for directory in (destination, destination / "config", destination / "infra", destination / "pki"):
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    readme = destination / "README.md"
    assert stat.S_IMODE(readme.stat().st_mode) == 0o600
    assert "# Platform Infrastructure Local Config" in readme.read_text(
        encoding="utf-8"
    )


def test_existing_namespace_is_secured_without_overwriting_files(
    tmp_path: Path, process_runner
) -> None:
    destination = tmp_path / "custom namespace"
    created = process_runner([TOOL, f"--config-dir={destination}"])
    assert created.status == 0
    readme = destination / "README.md"
    readme.write_text("keep this content\n", encoding="utf-8")
    readme.chmod(0o644)
    for directory in (destination, destination / "config", destination / "infra", destination / "pki"):
        directory.chmod(0o755)
    legacy = destination / "proxmox.env"
    legacy.write_text("legacy content\n", encoding="utf-8")

    result = process_runner([TOOL, "--config-dir", destination])

    assert result.status == 0
    assert readme.read_bytes() == b"keep this content\n"
    assert stat.S_IMODE(readme.stat().st_mode) == 0o600
    for directory in (destination, destination / "config", destination / "infra", destination / "pki"):
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert legacy.read_bytes() == b"legacy content\n"
    assert f"[INFO] Kept existing file: {readme}" in result.stdout
    assert result.stderr == (
        f"[WARN] Legacy path exists and was left unchanged: {legacy}\n"
    )


def test_literal_tilde_expands_against_home(tmp_path: Path, process_runner) -> None:
    home = tmp_path / "home"
    home.mkdir()
    environment = os.environ.copy()
    environment["HOME"] = os.fspath(home)

    result = process_runner(
        [TOOL, "--config-dir", "~/platform-test"], env=environment
    )

    assert result.status == 0
    assert result.stderr == ""
    assert stat.S_IMODE((home / "platform-test").stat().st_mode) == 0o700
