import json
import os
import re
import time
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
from pathlib import Path

import pytest

from ..harness import ProcessResult
from .conftest import RolloverTools, RolloverWorkspace
from .test_ca_rollover_prepare_recovery import (
    PRESENT_ROOT_DB_KEYS,
    VALID_TRUST_CONSUMERS,
    _assert_failed_control_state,
    _assert_rolled_back,
    _crash_after_staged,
    _crash_prepare,
    _metadata,
    _prepare_command,
    _read_public_journal,
    _read_strict_public_file,
    _read_strict_record,
    _recover,
)


pytestmark = pytest.mark.pki

TERMINAL_CHECKPOINTS = (
    "terminal-transaction-pending",
    "terminal-transaction-done",
    "terminal-journal-pending",
    "terminal-journal-done",
)
INTERMEDIATE_RECOVERY_BOUNDARIES = (
    "resume-publish-intermediate",
    "resume-consume-intermediate",
    "resume-cleanup-root-stage",
    "resume-publish-state",
    "resume-publish-pointer",
    "terminal-transaction",
    "terminal-journal",
)
ROOT_RESUME_RECOVERY_BOUNDARIES = (
    "resume-publish-root",
    "resume-publish-intermediate",
    "resume-consume-root",
    "resume-consume-intermediate",
    "resume-publish-state",
    "resume-publish-pointer",
    "terminal-transaction",
    "terminal-journal",
)
ROOT_ROLLBACK_RECOVERY_BOUNDARIES = (
    "rollback-pointer",
    "rollback-intermediate",
    "rollback-root",
    "rollback-state",
    "rollback-stage",
    "rollback-reservation-intermediate",
    "rollback-reservation-root",
    "rollback-backup-session",
    "terminal-transaction",
    "terminal-journal",
)
ROOT_MAJOR_ROLLBACK_STEPS = {
    "after-journal": "none",
    "after-consumed": "consume-intermediate-done",
}
ROOT_MAJOR_RESUME_STEPS = {
    "after-intermediate-candidate": "publish-intermediate-done",
    "after-state": "publish-state-done",
}


def _crash_recovery(
    tools: RolloverTools,
    workspace: RolloverWorkspace,
    transaction: str,
    action: str,
    checkpoint: str,
    environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> None:
    crash_environment = dict(environment)
    crash_environment["PLATFORM_PKI_RECOVER_CRASH_AT"] = checkpoint
    result = _recover(
        tools,
        workspace,
        transaction,
        action,
        crash_environment,
        process_runner,
    )
    assert result.status == 137, result
    assert result.stdout == ""
    assert result.stderr == ""

    journal_path = workspace.pki / "state/rollover/journal"
    marker_path = workspace.pki / "state/rollover/recovery-required"
    if checkpoint == "terminal-journal-done":
        assert not journal_path.exists() and not journal_path.is_symlink()
        marker = _read_strict_record(marker_path)
        assert marker["transaction"] == transaction
        assert marker["operation"] == "rollover-prepare"
        return

    terminal = checkpoint.startswith("terminal-")
    journal = _read_public_journal(
        journal_path,
        expected_committed="true" if terminal else "false",
    )
    assert journal["transaction"] == transaction
    assert journal["recovery_step"] == checkpoint
    if terminal:
        assert journal["phase"] == "terminal-cleanup"
        marker = _read_strict_record(marker_path)
        assert marker["transaction"] == transaction
        assert marker["operation"] == "rollover-prepare"
    else:
        assert not marker_path.exists() and not marker_path.is_symlink()


def _assert_resumed(
    workspace: RolloverWorkspace,
    transaction: str,
    candidate_root: str,
    candidate_intermediate: str,
) -> None:
    assert not (workspace.pki / "state/rollover/journal").exists()
    assert not (workspace.pki / "state/rollover/recovery-required").exists()
    assert not (workspace.pki / "state/rollover" / transaction).exists()
    root = workspace.pki / "authorities/roots" / candidate_root
    intermediate = workspace.pki / "authorities/intermediates" / candidate_intermediate
    assert root.is_dir() and not root.is_symlink()
    assert intermediate.is_dir() and not intermediate.is_symlink()

    state = workspace.pki / "state/rollovers" / transaction
    assert state.is_dir() and not state.is_symlink()
    manifest = _read_strict_record(state / "manifest")
    assert manifest["transaction"] == transaction
    assert manifest["candidate_root"] == candidate_root
    assert manifest["candidate_intermediate"] == candidate_intermediate
    tree_manifest, _ = _read_strict_public_file(state / "tree.manifest")
    pointer = _read_strict_record(workspace.pki / "state/active-rollover")
    assert pointer == {
        "transaction": transaction,
        "tree_manifest_sha256": sha256(tree_manifest).hexdigest(),
    }
    _read_strict_public_file(state / "candidate-intermediate-tree.manifest")
    if candidate_root != "g1":
        _read_strict_public_file(state / "candidate-root-tree.manifest")


def _assert_terminal_status(
    tools: RolloverTools,
    workspace: RolloverWorkspace,
    transaction: str,
    outcome: str,
    action: str,
    environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> None:
    common = {
        "schema": 2,
        "status": "recovery-required",
        "recovery_required": True,
        "transaction": transaction,
        "operation": "rollover-prepare",
        "phase": "terminal-cleanup",
        "terminal_outcome": outcome,
        "required_action": action,
    }
    result = process_runner(
        [
            tools.rollover,
            "status",
            "--namespace",
            workspace.namespace,
            "--format",
            "json",
        ],
        env=environment,
        timeout=30,
    )
    assert result.status == 2
    assert result.stderr == ""
    assert json.loads(result.stdout) == common

    result = process_runner(
        [
            tools.rollover,
            "status",
            "--namespace",
            workspace.namespace,
            "--format",
            "text",
        ],
        env=environment,
        timeout=30,
    )
    assert result.status == 2
    assert result.stderr == ""
    assert result.stdout == (
        "status=recovery-required\n"
        "recovery_required=true\n"
        f"transaction={transaction}\n"
        "operation=rollover-prepare\n"
        "phase=terminal-cleanup\n"
        f"terminal_outcome={outcome}\n"
        f"required_action={action}\n"
        "action=run platform-pki-ca-rollover recover --transaction "
        f"{transaction} --action {action}\n"
    )


def _wait_for_path(path: Path, timeout: float = 100) -> None:
    deadline = time.monotonic() + timeout
    while not path.exists():
        if time.monotonic() >= deadline:
            raise TimeoutError(f"timed out waiting for test hook: {path.name}")
        time.sleep(0.01)


def _root_crash_fixture(
    tools: RolloverTools,
    workspace: RolloverWorkspace,
    receipt: Path,
    checkpoint: str,
    expected_recovery_step: str,
    environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> dict[str, str]:
    return _crash_prepare(
        tools,
        workspace,
        receipt,
        "root",
        2,
        checkpoint,
        environment,
        process_runner,
        expected_recovery_step,
    )


def test_intermediate_resume_recovery_checkpoints(
    rollover_tools: RolloverTools,
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> None:
    workspace = rollover_case_factory("intermediate-resume-recovery-checkpoints")
    receipt = backup_receipt_factory(workspace)
    active = workspace.pki / "state/active-issuer"
    active_before = (active.read_text(), _metadata(active))
    journal, record, _ = _crash_after_staged(
        rollover_tools,
        workspace,
        receipt,
        isolated_environment,
        process_runner,
    )
    changed_keys = tuple(
        key
        for key in PRESENT_ROOT_DB_KEYS
        if record[f"root_{key}_pre_identity"]
        != record[f"root_{key}_post_identity"]
    )
    boundaries = (
        INTERMEDIATE_RECOVERY_BOUNDARIES[:1]
        + tuple(f"resume-root-db-{key}" for key in changed_keys)
        + INTERMEDIATE_RECOVERY_BOUNDARIES[1:]
    )
    assert changed_keys

    for boundary in boundaries:
        for suffix in ("pending", "done"):
            _crash_recovery(
                rollover_tools,
                workspace,
                journal["transaction"],
                "resume",
                f"{boundary}-{suffix}",
                isolated_environment,
                process_runner,
            )

    result = _recover(
        rollover_tools,
        workspace,
        journal["transaction"],
        "resume",
        isolated_environment,
        process_runner,
    )
    assert result.status == 0
    assert result.stderr == ""
    assert result.stdout == (
        f"[OK] Completed terminal cleanup for {journal['transaction']}\n"
    )
    assert (active.read_text(), _metadata(active)) == active_before
    _assert_resumed(workspace, journal["transaction"], "g1", "g1-i2")


def test_unexpected_candidate_tree_entry(
    rollover_tools: RolloverTools,
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> None:
    workspace = rollover_case_factory("unexpected-candidate-tree-entry")
    receipt = backup_receipt_factory(workspace)
    active = workspace.pki / "state/active-issuer"
    active_before = (active.read_text(), _metadata(active))
    journal, _, transaction_directory = _crash_after_staged(
        rollover_tools,
        workspace,
        receipt,
        isolated_environment,
        process_runner,
    )
    unexpected = transaction_directory / "stage/intermediate/unexpected"
    unexpected.write_text("hostile\n")
    unexpected.chmod(0o600)
    unexpected_before = _read_strict_public_file(unexpected)

    result = _recover(
        rollover_tools,
        workspace,
        journal["transaction"],
        "resume",
        isolated_environment,
        process_runner,
    )

    assert result.status == 1
    assert result.stdout == ""
    assert "tree contents do not match" in result.stderr
    assert _read_strict_public_file(unexpected) == unexpected_before
    _assert_failed_control_state(workspace, journal, expected_marker=False)
    assert (active.read_text(), _metadata(active)) == active_before


def test_interrupted_resume_terminal_status(
    rollover_tools: RolloverTools,
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> None:
    workspace = rollover_case_factory("interrupted-resume-terminal-status")
    receipt = backup_receipt_factory(workspace)
    active = workspace.pki / "state/active-issuer"
    active_before = (active.read_text(), _metadata(active))
    journal, _, _ = _crash_after_staged(
        rollover_tools,
        workspace,
        receipt,
        isolated_environment,
        process_runner,
    )
    for checkpoint in TERMINAL_CHECKPOINTS:
        _crash_recovery(
            rollover_tools,
            workspace,
            journal["transaction"],
            "resume",
            checkpoint,
            isolated_environment,
            process_runner,
        )
        _assert_terminal_status(
            rollover_tools,
            workspace,
            journal["transaction"],
            "resumed",
            "resume",
            isolated_environment,
            process_runner,
        )

    result = _recover(
        rollover_tools,
        workspace,
        journal["transaction"],
        "resume",
        isolated_environment,
        process_runner,
    )
    assert result.status == 0
    assert result.stdout == (
        f"[OK] Completed terminal cleanup for {journal['transaction']}\n"
    )
    assert result.stderr == ""
    _assert_resumed(workspace, journal["transaction"], "g1", "g1-i2")
    assert (active.read_text(), _metadata(active)) == active_before


def test_interrupted_rollback_terminal_status(
    rollover_tools: RolloverTools,
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    private_text_writer: Callable[[Path, str], None],
    process_runner: Callable[..., ProcessResult],
) -> None:
    workspace = rollover_case_factory("interrupted-rollback-terminal-status")
    private_text_writer(
        workspace.private_repo / "pki/trust-consumers.yml",
        VALID_TRUST_CONSUMERS,
    )
    receipt = backup_receipt_factory(workspace)
    active = workspace.pki / "state/active-issuer"
    active_before = (active.read_text(), _metadata(active))
    journal = _root_crash_fixture(
        rollover_tools,
        workspace,
        receipt,
        "after-pointer",
        "publish-pointer-done",
        isolated_environment,
        process_runner,
    )
    for checkpoint in TERMINAL_CHECKPOINTS:
        _crash_recovery(
            rollover_tools,
            workspace,
            journal["transaction"],
            "rollback",
            checkpoint,
            isolated_environment,
            process_runner,
        )
        _assert_terminal_status(
            rollover_tools,
            workspace,
            journal["transaction"],
            "rolled-back",
            "rollback",
            isolated_environment,
            process_runner,
        )

    result = _recover(
        rollover_tools,
        workspace,
        journal["transaction"],
        "rollback",
        isolated_environment,
        process_runner,
    )
    assert result.status == 0
    assert result.stdout == (
        f"[OK] Completed terminal cleanup for {journal['transaction']}\n"
    )
    assert result.stderr == ""
    _assert_rolled_back(workspace, journal["transaction"], "g2", "g2-i1")
    assert (active.read_text(), _metadata(active)) == active_before


def test_prepare_terminal_journal_unlink_race(
    rollover_tools: RolloverTools,
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> None:
    workspace = rollover_case_factory("prepare-terminal-journal-unlink-race")
    receipt = backup_receipt_factory(workspace)
    active = workspace.pki / "state/active-issuer"
    active_before = (active.read_text(), _metadata(active))
    pause_marker = workspace.root / "pause-marker"
    pause_release = workspace.root / "pause-release"
    environment = dict(isolated_environment)
    environment.update(
        {
            "PLATFORM_PKI_UNLINK_PAUSE_AT": "terminal-journal",
            "PLATFORM_PKI_UNLINK_PAUSE_MARKER": os.fspath(pause_marker),
            "PLATFORM_PKI_UNLINK_PAUSE_RELEASE": os.fspath(pause_release),
        }
    )

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(
            process_runner,
            _prepare_command(rollover_tools, workspace, receipt, "intermediate", 2),
            env=environment,
            timeout=120,
        )
        try:
            _wait_for_path(pause_marker)
            journal = workspace.pki / "state/rollover/journal"
            journal.rename(workspace.root / "original-journal")
            journal.write_text("hostile-journal\n")
            journal.chmod(0o600)
            hostile_before = _read_strict_public_file(journal)
        finally:
            pause_release.touch(mode=0o600, exist_ok=True)
        result = future.result(timeout=125)

    assert result.status == 1
    assert result.stdout == ""
    assert "journal changed before terminal unlink" in result.stderr
    assert _read_strict_public_file(journal) == hostile_before
    assert (active.read_text(), _metadata(active)) == active_before


def test_recover_terminal_marker_unlink_race(
    rollover_tools: RolloverTools,
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> None:
    workspace = rollover_case_factory("recover-terminal-marker-unlink-race")
    receipt = backup_receipt_factory(workspace)
    active = workspace.pki / "state/active-issuer"
    active_before = (active.read_text(), _metadata(active))
    journal, _, _ = _crash_after_staged(
        rollover_tools,
        workspace,
        receipt,
        isolated_environment,
        process_runner,
    )
    pause_marker = workspace.root / "pause-marker"
    pause_release = workspace.root / "pause-release"
    environment = dict(isolated_environment)
    environment.update(
        {
            "PLATFORM_PKI_UNLINK_PAUSE_AT": "terminal-marker",
            "PLATFORM_PKI_UNLINK_PAUSE_MARKER": os.fspath(pause_marker),
            "PLATFORM_PKI_UNLINK_PAUSE_RELEASE": os.fspath(pause_release),
        }
    )

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(
            _recover,
            rollover_tools,
            workspace,
            journal["transaction"],
            "resume",
            environment,
            process_runner,
        )
        try:
            _wait_for_path(pause_marker)
            marker = workspace.pki / "state/rollover/recovery-required"
            marker.rename(workspace.root / "original-marker")
            marker.write_text("hostile-marker\n")
            marker.chmod(0o600)
            hostile_before = _read_strict_public_file(marker)
        finally:
            pause_release.touch(mode=0o600, exist_ok=True)
        result = future.result(timeout=125)

    assert result.status == 1
    assert result.stdout == ""
    assert "marker changed before terminal unlink" in result.stderr
    assert _read_strict_public_file(marker) == hostile_before
    assert not (workspace.pki / "state/rollover/journal").exists()
    assert (active.read_text(), _metadata(active)) == active_before


@pytest.mark.parametrize("checkpoint", tuple(ROOT_MAJOR_ROLLBACK_STEPS))
def test_root_major_boundary_rollback(
    rollover_tools: RolloverTools,
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    private_text_writer: Callable[[Path, str], None],
    process_runner: Callable[..., ProcessResult],
    checkpoint: str,
) -> None:
    workspace = rollover_case_factory(f"root-major-rollback-{checkpoint}")
    private_text_writer(
        workspace.private_repo / "pki/trust-consumers.yml",
        VALID_TRUST_CONSUMERS,
    )
    receipt = backup_receipt_factory(workspace)
    active = workspace.pki / "state/active-issuer"
    active_before = (active.read_text(), _metadata(active))
    journal = _root_crash_fixture(
        rollover_tools,
        workspace,
        receipt,
        checkpoint,
        ROOT_MAJOR_ROLLBACK_STEPS[checkpoint],
        isolated_environment,
        process_runner,
    )
    result = _recover(
        rollover_tools,
        workspace,
        journal["transaction"],
        "rollback",
        isolated_environment,
        process_runner,
    )
    assert result.status == 0
    assert result.stderr == ""
    prefix = "planned " if checkpoint == "after-journal" else ""
    assert result.stdout == (
        f"[OK] Rolled back {prefix}preparation transaction: "
        f"{journal['transaction']}\n"
    )
    _assert_rolled_back(workspace, journal["transaction"], "g2", "g2-i1")
    assert (active.read_text(), _metadata(active)) == active_before


@pytest.mark.parametrize("checkpoint", tuple(ROOT_MAJOR_RESUME_STEPS))
def test_root_major_boundary_resume(
    rollover_tools: RolloverTools,
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    private_text_writer: Callable[[Path, str], None],
    process_runner: Callable[..., ProcessResult],
    checkpoint: str,
) -> None:
    workspace = rollover_case_factory(f"root-major-resume-{checkpoint}")
    private_text_writer(
        workspace.private_repo / "pki/trust-consumers.yml",
        VALID_TRUST_CONSUMERS,
    )
    receipt = backup_receipt_factory(workspace)
    active = workspace.pki / "state/active-issuer"
    active_before = (active.read_text(), _metadata(active))
    journal = _root_crash_fixture(
        rollover_tools,
        workspace,
        receipt,
        checkpoint,
        ROOT_MAJOR_RESUME_STEPS[checkpoint],
        isolated_environment,
        process_runner,
    )
    result = _recover(
        rollover_tools,
        workspace,
        journal["transaction"],
        "resume",
        isolated_environment,
        process_runner,
    )
    assert result.status == 0
    assert result.stderr == ""
    assert result.stdout == (
        f"[OK] Resumed preparation transaction: {journal['transaction']}\n"
    )
    assert (active.read_text(), _metadata(active)) == active_before
    _assert_resumed(workspace, journal["transaction"], "g2", "g2-i1")


def test_replaced_published_root_candidate(
    rollover_tools: RolloverTools,
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    private_text_writer: Callable[[Path, str], None],
    process_runner: Callable[..., ProcessResult],
) -> None:
    workspace = rollover_case_factory("replaced-published-root-candidate")
    private_text_writer(
        workspace.private_repo / "pki/trust-consumers.yml",
        VALID_TRUST_CONSUMERS,
    )
    receipt = backup_receipt_factory(workspace)
    active = workspace.pki / "state/active-issuer"
    active_before = (active.read_text(), _metadata(active))
    journal = _root_crash_fixture(
        rollover_tools,
        workspace,
        receipt,
        "after-root-candidate",
        "publish-root-done",
        isolated_environment,
        process_runner,
    )
    certificate = workspace.pki / "authorities/roots/g2/certs/root-ca.crt"
    certificate.write_text("hostile-candidate\n")
    certificate.chmod(0o600)
    hostile_before = _read_strict_public_file(certificate)

    result = _recover(
        rollover_tools,
        workspace,
        journal["transaction"],
        "rollback",
        isolated_environment,
        process_runner,
    )
    assert result.status == 1
    assert result.stdout == ""
    assert "Candidate root certificate" in result.stderr
    assert _read_strict_public_file(certificate) == hostile_before
    _assert_failed_control_state(workspace, journal, expected_marker=False)
    assert (active.read_text(), _metadata(active)) == active_before


def test_root_resume_recovery_checkpoints(
    rollover_tools: RolloverTools,
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    private_text_writer: Callable[[Path, str], None],
    process_runner: Callable[..., ProcessResult],
) -> None:
    workspace = rollover_case_factory("root-resume-recovery-checkpoints")
    private_text_writer(
        workspace.private_repo / "pki/trust-consumers.yml",
        VALID_TRUST_CONSUMERS,
    )
    receipt = backup_receipt_factory(workspace)
    active = workspace.pki / "state/active-issuer"
    active_before = (active.read_text(), _metadata(active))
    journal = _root_crash_fixture(
        rollover_tools,
        workspace,
        receipt,
        "after-staged",
        "evidence-stage-done",
        isolated_environment,
        process_runner,
    )
    for boundary in ROOT_RESUME_RECOVERY_BOUNDARIES:
        for suffix in ("pending", "done"):
            _crash_recovery(
                rollover_tools,
                workspace,
                journal["transaction"],
                "resume",
                f"{boundary}-{suffix}",
                isolated_environment,
                process_runner,
            )

    result = _recover(
        rollover_tools,
        workspace,
        journal["transaction"],
        "resume",
        isolated_environment,
        process_runner,
    )
    assert result.status == 0
    assert result.stderr == ""
    assert result.stdout == (
        f"[OK] Completed terminal cleanup for {journal['transaction']}\n"
    )
    assert (active.read_text(), _metadata(active)) == active_before
    _assert_resumed(workspace, journal["transaction"], "g2", "g2-i1")


def test_root_rollback_recovery_checkpoints(
    rollover_tools: RolloverTools,
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    private_text_writer: Callable[[Path, str], None],
    process_runner: Callable[..., ProcessResult],
) -> None:
    workspace = rollover_case_factory("root-rollback-recovery-checkpoints")
    private_text_writer(
        workspace.private_repo / "pki/trust-consumers.yml",
        VALID_TRUST_CONSUMERS,
    )
    receipt = backup_receipt_factory(workspace)
    active = workspace.pki / "state/active-issuer"
    active_before = (active.read_text(), _metadata(active))
    journal = _root_crash_fixture(
        rollover_tools,
        workspace,
        receipt,
        "after-pointer",
        "publish-pointer-done",
        isolated_environment,
        process_runner,
    )
    for boundary in ROOT_ROLLBACK_RECOVERY_BOUNDARIES:
        for suffix in ("pending", "done"):
            _crash_recovery(
                rollover_tools,
                workspace,
                journal["transaction"],
                "rollback",
                f"{boundary}-{suffix}",
                isolated_environment,
                process_runner,
            )
            if boundary.startswith("terminal-"):
                _assert_terminal_status(
                    rollover_tools,
                    workspace,
                    journal["transaction"],
                    "rolled-back",
                    "rollback",
                    isolated_environment,
                    process_runner,
                )

    result = _recover(
        rollover_tools,
        workspace,
        journal["transaction"],
        "rollback",
        isolated_environment,
        process_runner,
    )
    assert result.status == 0
    assert result.stderr == ""
    assert result.stdout == (
        f"[OK] Completed terminal cleanup for {journal['transaction']}\n"
    )
    assert (active.read_text(), _metadata(active)) == active_before
    _assert_rolled_back(workspace, journal["transaction"], "g2", "g2-i1")
    rollover_state = workspace.pki / "state/rollovers" / journal["transaction"]
    assert not rollover_state.exists() and not rollover_state.is_symlink()
    assert not tuple((workspace.pki / "state/rollover").glob("backup-session-*"))
    for generation, kind in (("g2", "root"), ("g2-i1", "intermediate")):
        reservation = _read_strict_record(
            workspace.pki / "state/generation-reservations" / generation
        )
        assert reservation == {
            "generation": generation,
            "kind": kind,
            "status": "abandoned",
            "transaction": journal["transaction"],
        }
