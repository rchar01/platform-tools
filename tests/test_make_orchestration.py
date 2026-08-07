import os
import shutil
import tempfile
from collections.abc import Generator
from pathlib import Path

import pytest


pytestmark = pytest.mark.infrastructure

REPO_ROOT = Path(__file__).resolve().parents[1]
EXPECTED_NON_ROLLOVER_TARGETS = {
    "test-python-infrastructure",
    "test-command-contract",
    "test-installed-tools",
    "test-platform-config-init",
    "test-platform-ssh-init",
    "test-vm-env-collect-cli",
    "test-bastion-policy",
    "test-proxmox-token-init",
    "test-proxmox-vm-cleanup",
    "test-proxmox-vm-snapshot",
    "test-pki-init",
    "test-pki-root-create",
    "test-pki-intermediate-create",
    "test-pki-service-issue",
    "test-pki-service-renew",
    "test-pki-print-cert",
    "test-pki-list-expiry",
    "test-pki-service-verify",
    "test-pki-pass-file",
    "test-pki-legacy-gating",
    "test-pki-backup",
    "test-pki-custody-report",
    "test-pki-ca-passphrase-verify",
    "test-pki-export",
    "test-pki-certificate-export",
    "test-pki-csr-candidate",
    "test-pki-inventory",
    "test-pki-inventory-install",
    "test-pki-csr-trust-install",
    "test-pki-csr-signing",
}


@pytest.fixture
def executable_directory() -> Generator[Path, None, None]:
    parent = REPO_ROOT / ".tmp"
    parent.mkdir(mode=0o700, exist_ok=True)
    path = Path(tempfile.mkdtemp(prefix="pytest-make-exec.", dir=parent))
    try:
        yield path
    finally:
        shutil.rmtree(path)


def _fake_make(tmp_path: Path) -> tuple[Path, dict[str, str]]:
    fake = tmp_path / "fake-make"
    log = tmp_path / "make.log"
    marker = tmp_path / "non-rollover-complete"
    fake.write_text(
        """#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$MAKE_TEST_LOG"
target=${!#}
case "$target" in
  test-non-rollover)
    if [[ ${MAKE_TEST_FAIL_FIRST:-0} == 1 ]]; then
      exit 23
    fi
    : >"$MAKE_TEST_MARKER"
    ;;
  test-pki-ca-rollover)
    [[ -f $MAKE_TEST_MARKER ]] || exit 24
    ;;
  *)
    exit 25
    ;;
esac
""",
        encoding="utf-8",
    )
    env = os.environ.copy()
    env.update(
        {
            "MAKE_TEST_LOG": str(log),
            "MAKE_TEST_MARKER": str(marker),
        }
    )
    return fake, env


def _run_test_target(process_runner, fake: Path, env: dict[str, str], *variables: str):
    return process_runner(
        [
            "make",
            "--no-print-directory",
            "test",
            f"MAKE=bash {fake}",
            *variables,
        ],
        cwd=REPO_ROOT,
        env=env,
    )


def _fake_podman(executable_directory: Path) -> tuple[Path, dict[str, str]]:
    fake_podman = executable_directory / "podman"
    log = executable_directory / "podman.log"
    fake_podman.write_text(
        """#!/usr/bin/env bash
set -euo pipefail
for argument in "$@"; do
  printf 'arg=%s\n' "$argument" >>"$PODMAN_TEST_LOG"
done
printf '%s\n' 'end-call' >>"$PODMAN_TEST_LOG"
""",
        encoding="utf-8",
    )
    fake_podman.chmod(0o755)
    env = os.environ.copy()
    env.pop("PLATFORM_TOOLS_DEV_IMAGE", None)
    env.pop("PLATFORM_TOOLS_TEST_IMAGE", None)
    env["PATH"] = f"{executable_directory}{os.pathsep}{env['PATH']}"
    env["PODMAN_TEST_LOG"] = str(log)
    return log, env


def _podman_calls(log: Path) -> list[list[str]]:
    calls: list[list[str]] = [[]]
    for line in log.read_text(encoding="utf-8").splitlines():
        if line == "end-call":
            calls.append([])
        else:
            calls[-1].append(line.removeprefix("arg="))
    assert calls[-1] == []
    return calls[:-1]


def test_non_rollover_target_inventory_is_exact() -> None:
    assignment = next(
        line
        for line in (REPO_ROOT / "Makefile").read_text(encoding="utf-8").splitlines()
        if line.startswith("NON_ROLLOVER_TEST_TARGETS := ")
    )
    targets = assignment.partition(":= ")[2].split()

    assert len(targets) == len(set(targets))
    assert set(targets) == EXPECTED_NON_ROLLOVER_TARGETS


def test_test_target_runs_bounded_pool_before_rollover(tmp_path, process_runner) -> None:
    fake, env = _fake_make(tmp_path)

    result = _run_test_target(
        process_runner,
        fake,
        env,
        "TEST_MAKE_JOBS=3",
        "PKI_PYTEST_WORKERS=2",
    )

    assert result.status == 0, result.stderr
    assert (tmp_path / "make.log").read_text(encoding="utf-8").splitlines() == [
        "--no-print-directory --jobs=3 --output-sync=target test-non-rollover",
        "--no-print-directory test-pki-ca-rollover",
    ]


def test_test_target_stops_before_rollover_on_pool_failure(
    tmp_path, process_runner
) -> None:
    fake, env = _fake_make(tmp_path)
    env["MAKE_TEST_FAIL_FIRST"] = "1"

    result = _run_test_target(
        process_runner,
        fake,
        env,
        "TEST_MAKE_JOBS=2",
        "PKI_PYTEST_WORKERS=4",
    )

    assert result.status == 2
    assert (tmp_path / "make.log").read_text(encoding="utf-8").splitlines() == [
        "--no-print-directory --jobs=2 --output-sync=target test-non-rollover"
    ]


@pytest.mark.parametrize(
    ("variable", "value"),
    [
        ("TEST_MAKE_JOBS", ""),
        ("TEST_MAKE_JOBS", "0"),
        ("TEST_MAKE_JOBS", "5"),
        ("TEST_MAKE_JOBS", "auto"),
        ("PKI_PYTEST_WORKERS", ""),
        ("PKI_PYTEST_WORKERS", "0"),
        ("PKI_PYTEST_WORKERS", "5"),
        ("PKI_PYTEST_WORKERS", "auto"),
    ],
)
def test_test_target_rejects_invalid_workers_before_starting_tests(
    tmp_path, process_runner, variable: str, value: str
) -> None:
    fake, env = _fake_make(tmp_path)

    result = _run_test_target(process_runner, fake, env, f"{variable}={value}")

    assert result.status == 2
    assert f"{variable} must be an integer from 1 through 4" in result.stderr
    assert not (tmp_path / "make.log").exists()


@pytest.mark.parametrize("value", ["", "0", "5", "auto"])
def test_standalone_rollover_rejects_invalid_workers_before_xdist(
    tmp_path, process_runner, value: str
) -> None:
    fake_python = tmp_path / "python3"
    fake_python.symlink_to("/bin/false")
    env = os.environ.copy()
    env["PATH"] = f"{tmp_path}{os.pathsep}{env['PATH']}"
    result = process_runner(
        [
            "make",
            "--no-print-directory",
            "test-python-pki-rollover-parallel",
            f"PKI_PYTEST_WORKERS={value}",
        ],
        cwd=REPO_ROOT,
        env=env,
    )

    assert result.status == 2
    assert "PKI_PYTEST_WORKERS must be an integer from 1 through 4" in result.stderr
    assert "pytest-xdist is required" not in result.stderr


@pytest.mark.parametrize(
    ("worker_env", "expected_jobs", "expected_workers"),
    [
        ({}, "2", "4"),
        ({"TEST_MAKE_JOBS": "", "PKI_PYTEST_WORKERS": ""}, "", ""),
    ],
)
def test_test_container_wrapper_preserves_worker_values(
    executable_directory: Path,
    process_runner,
    worker_env: dict[str, str],
    expected_jobs: str,
    expected_workers: str,
) -> None:
    log, env = _fake_podman(executable_directory)
    env.pop("TEST_MAKE_JOBS", None)
    env.pop("PKI_PYTEST_WORKERS", None)
    env.update(worker_env)

    result = process_runner(
        ["bash", str(REPO_ROOT / "scripts/in-test-container"), "true"],
        cwd=REPO_ROOT,
        env=env,
    )

    assert result.status == 0, result.stderr
    build, run = _podman_calls(log)
    assert f"TEST_MAKE_JOBS={expected_jobs}" in run
    assert f"PKI_PYTEST_WORKERS={expected_workers}" in run
    assert "PLATFORM_TOOLS_TEST_CONTAINER=1" in run
    assert "PLATFORM_TOOLS_DEV_CONTAINER=1" not in run
    assert str(REPO_ROOT / "Containerfile.test") in build
    assert "localhost/platform-tools-test:3.14.7" in build
    assert "localhost/platform-tools-test:3.14.7" in run


def test_development_container_wrapper_uses_bashly_image(
    executable_directory: Path, process_runner
) -> None:
    log, env = _fake_podman(executable_directory)

    result = process_runner(
        ["bash", str(REPO_ROOT / "scripts/in-container"), "true"],
        cwd=REPO_ROOT,
        env=env,
    )

    assert result.status == 0, result.stderr
    build, run = _podman_calls(log)
    assert "PLATFORM_TOOLS_DEV_CONTAINER=1" in run
    assert "PLATFORM_TOOLS_TEST_CONTAINER=1" not in run
    assert str(REPO_ROOT / "Containerfile.dev") in build
    assert "localhost/platform-tools-dev:2.2.0" in build
    assert "localhost/platform-tools-dev:2.2.0" in run
    assert not any("TEST_MAKE_JOBS=" in argument for argument in run)
    assert not any("PKI_PYTEST_WORKERS=" in argument for argument in run)


def test_container_check_runs_bashly_phase_before_test_phase(
    executable_directory: Path, process_runner
) -> None:
    log, env = _fake_podman(executable_directory)

    result = process_runner(
        ["make", "--no-print-directory", "container-check"],
        cwd=REPO_ROOT,
        env=env,
    )

    assert result.status == 0, result.stderr
    calls = _podman_calls(log)
    assert len(calls) == 4
    assert str(REPO_ROOT / "Containerfile.dev") in calls[0]
    assert calls[1][-3:] == ["make", "verify-generated", "shellcheck"]
    assert str(REPO_ROOT / "Containerfile.test") in calls[2]
    assert calls[3][-1] == "./scripts/check"


def test_check_script_runs_test_image_phases_once_in_order(
    executable_directory: Path, process_runner
) -> None:
    fake_make = executable_directory / "make"
    log = executable_directory / "make.log"
    fake_make.write_text(
        """#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$MAKE_TEST_LOG"
""",
        encoding="utf-8",
    )
    fake_make.chmod(0o755)
    env = os.environ.copy()
    env["PATH"] = f"{executable_directory}{os.pathsep}{env['PATH']}"
    env["MAKE_TEST_LOG"] = str(log)

    result = process_runner(
        ["bash", str(REPO_ROOT / "scripts/check")], cwd=REPO_ROOT, env=env
    )

    assert result.status == 0, result.stderr
    assert log.read_text(encoding="utf-8").splitlines() == [
        "verify",
        "test",
        "test-vm-env-collect-archive",
    ]
