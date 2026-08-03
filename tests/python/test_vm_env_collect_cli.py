from __future__ import annotations

import os
from pathlib import Path

import pytest

from .harness import ProcessResult


ROOT_DIR = Path(__file__).resolve().parents[2]
TOOL = ROOT_DIR / "bin/platform-vm-env-collect"
SOURCE = ROOT_DIR / "bashly/platform-vm-env-collect/src/root_command.sh"


def run_collector_cli(process_runner, *arguments: str, env=None) -> ProcessResult:
    return process_runner((TOOL, *arguments), env=env, timeout=30)


def test_help_documents_environment(process_runner) -> None:
    result = run_collector_cli(process_runner, "--help")

    assert result.status == 0
    assert "Environment Variables:" in result.stdout
    assert "INCLUDE_SENSITIVE" in result.stdout
    assert "COLLECT_ENV" in result.stdout
    assert result.stderr == ""


def test_version(process_runner) -> None:
    version = (ROOT_DIR / "VERSION").read_text().strip()

    result = run_collector_cli(process_runner, "--version")

    assert result.status == 0
    assert result.stdout == f"platform-vm-env-collect {version}\n"
    assert result.stderr == ""


def test_unknown_option_is_rejected(process_runner) -> None:
    result = run_collector_cli(process_runner, "--unknown")

    assert result.status == 1
    assert result.stdout == ""
    assert "invalid option: --unknown" in result.stderr


@pytest.mark.parametrize(
    ("name", "value"),
    (("INCLUDE_SENSITIVE", "2"), ("COLLECT_ENV", "yes")),
    ids=("include-sensitive", "collect-env"),
)
def test_invalid_environment_is_rejected(
    process_runner, name: str, value: str
) -> None:
    env = os.environ.copy()
    env[name] = value

    result = run_collector_cli(process_runner, env=env)

    assert result.status == 1
    assert result.stdout == ""
    assert f"{name} environment variable must be one of: 0, 1" in result.stderr


def test_report_format_version() -> None:
    assert 'SCRIPT_VERSION="1.1.0"' in SOURCE.read_text()
