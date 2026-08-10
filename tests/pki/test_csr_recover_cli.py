from __future__ import annotations

import fcntl
import time
from collections.abc import Callable, Mapping
from pathlib import Path

import pytest

from ..harness import ManagedProcess, ProcessResult
from .support import BIN, write_private


pytestmark = pytest.mark.pki

TOOL = BIN / "platform-pki-csr-recover"
UNIFIED = BIN / "platform-pki"
TRANSACTION = "csr-0123456789abcdef0123456789abcdef"


def _pki(tmp_path: Path) -> Path:
    pki = tmp_path / "pki"
    (pki / "state/csr").mkdir(mode=0o700, parents=True)
    pki.chmod(0o700)
    (pki / "state").chmod(0o700)
    return pki


def _run(
    runner: Callable[..., ProcessResult],
    environment: Mapping[str, str],
    command: Path,
    *arguments: str | Path,
) -> ProcessResult:
    prefix: tuple[str | Path, ...] = (command,)
    if command == UNIFIED:
        prefix += ("csr-recover",)
    return runner((*prefix, *arguments), env=environment)


@pytest.mark.parametrize("command", (TOOL, UNIFIED), ids=("compatibility", "unified"))
def test_public_routes_share_transaction_validation(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    isolated_environment: Mapping[str, str],
    command: Path,
) -> None:
    result = _run(
        process_runner,
        isolated_environment,
        command,
        "--pki-dir",
        tmp_path / "missing",
        "--transaction",
        "csr-invalid",
        "--yes",
    )
    assert result.status == 1
    assert result.stdout == ""
    assert result.stderr == "[ERROR] CSR recovery transaction ID is invalid\n"


def test_public_selection_rejects_missing_and_ambiguous_journals_before_options(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    isolated_environment: Mapping[str, str],
) -> None:
    pki = _pki(tmp_path)
    missing = _run(
        process_runner,
        isolated_environment,
        TOOL,
        "--pki-dir",
        pki,
        "--transaction",
        TRANSACTION,
        "--yes",
    )
    assert missing.stderr == "[ERROR] No CSR recovery journal exists\n"

    write_private(pki / "state/csr/recovery-journal", "invalid\n")
    write_private(pki / "state/csr/finalization-recovery-journal", "invalid\n")
    ambiguous = _run(
        process_runner,
        isolated_environment,
        TOOL,
        "--pki-dir",
        pki,
        "--response-key",
        tmp_path / "response-key",
        "--yes",
    )
    assert ambiguous.stderr == "[ERROR] CSR recovery journal state is ambiguous\n"


def test_public_selection_enforces_kind_specific_options_before_confirmation(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    isolated_environment: Mapping[str, str],
) -> None:
    pki = _pki(tmp_path)
    signing = pki / "state/csr/recovery-journal"
    finalization = pki / "state/csr/finalization-recovery-journal"
    write_private(signing, "invalid\n")
    missing_transaction = _run(
        process_runner,
        isolated_environment,
        TOOL,
        "--pki-dir",
        pki,
    )
    assert missing_transaction.stderr == (
        "[ERROR] --transaction is required for CSR signing recovery\n"
    )

    signing.unlink()
    write_private(finalization, "invalid\n")
    response_key = _run(
        process_runner,
        isolated_environment,
        TOOL,
        "--pki-dir",
        pki,
        "--response-key",
        tmp_path / "response-key",
    )
    assert response_key.stderr == (
        "[ERROR] --response-key is not accepted for candidate finalization recovery\n"
    )


def _wait_for_prompt(process: ManagedProcess, expected: str) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        observation = process.observe()
        if expected in observation.stderr:
            return
        if observation.status is not None:
            pytest.fail(f"recovery exited before confirmation: {observation}")
        time.sleep(0.01)
    pytest.fail("recovery confirmation prompt was not observed")


@pytest.mark.parametrize("race", ("switched", "both", "disappeared"))
def test_public_confirmation_rechecks_selected_journal_without_switching(
    tmp_path: Path,
    process_starter: Callable[..., ManagedProcess],
    isolated_environment: Mapping[str, str],
    race: str,
) -> None:
    pki = _pki(tmp_path)
    signing = pki / "state/csr/recovery-journal"
    finalization = pki / "state/csr/finalization-recovery-journal"
    write_private(signing, "invalid\n")
    prompt = f"Type recover {TRANSACTION} to continue: "
    process = process_starter(
        [TOOL, "--pki-dir", pki, "--transaction", TRANSACTION],
        env=isolated_environment,
        pty_mode="canonical",
        controlling_terminal=True,
    )
    with process:
        _wait_for_prompt(process, prompt)
        if race in {"switched", "disappeared"}:
            signing.unlink()
        if race in {"switched", "both"}:
            write_private(finalization, "invalid\n")
        process.write(f"recover {TRANSACTION}\n")
        process.send_eof()
        result = process.wait()

    assert result.status == 1
    assert result.stderr == (
        f"{prompt}[ERROR] CSR recovery journal state changed after confirmation\n"
    )
    assert signing.is_file() is (race == "both")
    assert finalization.is_file() is (race in {"switched", "both"})
    if signing.is_file():
        assert signing.read_text() == "invalid\n"
    if finalization.is_file():
        assert finalization.read_text() == "invalid\n"


def test_public_finalization_confirmation_is_exact(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    isolated_environment: Mapping[str, str],
) -> None:
    pki = _pki(tmp_path)
    write_private(pki / "state/csr/finalization-recovery-journal", "invalid\n")
    result = process_runner(
        [TOOL, "--pki-dir", pki],
        env=isolated_environment,
        input="recover finalization\n",
        pty_mode="canonical",
        controlling_terminal=True,
    )
    assert result.status == 1
    assert result.stderr == (
        "Type recover candidate finalization to continue: "
        "[ERROR] CSR recovery confirmation did not match\n"
    )


def test_public_confirmation_requires_stdin_tty(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    isolated_environment: Mapping[str, str],
) -> None:
    pki = _pki(tmp_path)
    write_private(pki / "state/csr/recovery-journal", "invalid\n")
    result = _run(
        process_runner,
        isolated_environment,
        TOOL,
        "--pki-dir",
        pki,
        "--transaction",
        TRANSACTION,
    )
    assert result.status == 1
    assert result.stderr == "[ERROR] CSR recovery requires a TTY or --yes\n"


def test_public_recovery_uses_kind_specific_lock_profile(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    isolated_environment: Mapping[str, str],
) -> None:
    pki = _pki(tmp_path)
    locks = pki / "locks"
    locks.mkdir(mode=0o700)
    for name in ("lifecycle", "root", "intermediate", "inventory", "export"):
        write_private(locks / name, "")
    signing = pki / "state/csr/recovery-journal"
    finalization = pki / "state/csr/finalization-recovery-journal"
    write_private(signing, "invalid\n")

    with (locks / "export").open("r+") as export_lock:
        fcntl.flock(export_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        signing_result = _run(
            process_runner,
            isolated_environment,
            TOOL,
            "--pki-dir",
            pki,
            "--transaction",
            TRANSACTION,
            "--yes",
        )
        assert "Another " not in signing_result.stderr
        assert "CSR recovery requires complete generation-aware PKI state" in (
            signing_result.stderr
        )

        signing.unlink()
        write_private(finalization, "invalid\n")
        finalization_result = _run(
            process_runner,
            isolated_environment,
            TOOL,
            "--pki-dir",
            pki,
            "--yes",
        )
        assert finalization_result.stderr == (
            f"[ERROR] Another export operation is in progress: {locks}/export\n"
        )
