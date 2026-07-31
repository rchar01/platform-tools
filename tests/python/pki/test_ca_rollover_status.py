import stat
from collections.abc import Callable, Mapping
from hashlib import sha256
from pathlib import Path

import pytest

from ..harness import ProcessResult
from .conftest import RolloverWorkspace


pytestmark = pytest.mark.pki


def control_tree_snapshot(pki: Path) -> tuple[str, ...]:
    entries = []
    for path in (pki, *sorted(pki.rglob("*"))):
        metadata = path.lstat()
        relative = "." if path == pki else path.relative_to(pki).as_posix()
        mode = stat.S_IMODE(metadata.st_mode)
        identity = f"{metadata.st_dev}:{metadata.st_ino}:{metadata.st_nlink}"
        if stat.S_ISDIR(metadata.st_mode):
            detail = "directory"
        elif stat.S_ISREG(metadata.st_mode):
            detail = sha256(path.read_bytes()).hexdigest()
        else:
            detail = f"other:{stat.S_IFMT(metadata.st_mode):o}"
        entries.append(
            f"{relative}\t{mode:o}\t{identity}\t{metadata.st_size}\t"
            f"{metadata.st_mtime_ns}\t{detail}"
        )
    return tuple(entries)


def create_status_control_workspace(
    name: str,
    factory: Callable[[str], RolloverWorkspace],
    private_text_writer: Callable[[Path, str], None],
) -> RolloverWorkspace:
    workspace = factory(name)
    assert not workspace.passphrase_file.exists()
    assert not workspace.private_repo.exists()
    control_directories = (
        workspace.namespace,
        workspace.pki,
        workspace.pki / "locks",
        workspace.pki / "state",
        workspace.pki / "state/rollover",
        workspace.pki / "state/rollovers",
        workspace.pki / "state/generation-reservations",
    )
    for directory in control_directories:
        directory.mkdir(mode=0o700)
        directory.chmod(0o700)
    for lock in ("lifecycle", "root", "intermediate", "inventory", "export"):
        private_text_writer(workspace.pki / "locks" / lock, "")
    return workspace


def test_status_rejects_invalid_terminal_marker(
    rollover_tools,
    rollover_control_workspace_factory: Callable[[str], RolloverWorkspace],
    isolated_environment: Mapping[str, str],
    private_text_writer: Callable[[Path, str], None],
    public_state_snapshot: Callable[[RolloverWorkspace], tuple[str, ...]],
    process_runner: Callable[..., ProcessResult],
) -> None:
    workspace = create_status_control_workspace(
        "invalid-terminal-marker",
        rollover_control_workspace_factory,
        private_text_writer,
    )

    marker = workspace.pki / "state/rollover/recovery-required"
    private_text_writer(
        marker,
        "transaction=prepare-root-20260730-000000-1\n"
        "operation=rollover-prepare\n"
        "terminal_outcome=invalid\n",
    )
    before = public_state_snapshot(workspace)
    control_before = control_tree_snapshot(workspace.pki)

    result = process_runner(
        [
            rollover_tools.rollover,
            "status",
            "--namespace",
            workspace.namespace,
            "--format",
            "json",
        ],
        env=isolated_environment,
        timeout=10,
    )

    assert result.status == 1
    assert result.stdout == ""
    assert result.stderr == (
        "[ERROR] PKI recovery marker has invalid terminal preparation state\n"
    )
    assert public_state_snapshot(workspace) == before
    assert control_tree_snapshot(workspace.pki) == control_before
    assert marker.read_text() == (
        "transaction=prepare-root-20260730-000000-1\n"
        "operation=rollover-prepare\n"
        "terminal_outcome=invalid\n"
    )


def test_status_reports_unresolved_migration_journal(
    rollover_tools,
    rollover_control_workspace_factory: Callable[[str], RolloverWorkspace],
    isolated_environment: Mapping[str, str],
    private_text_writer: Callable[[Path, str], None],
    public_state_snapshot: Callable[[RolloverWorkspace], tuple[str, ...]],
    process_runner: Callable[..., ProcessResult],
) -> None:
    workspace = create_status_control_workspace(
        "unresolved-migration-journal",
        rollover_control_workspace_factory,
        private_text_writer,
    )
    journal = workspace.pki / "state/rollover/journal"
    private_text_writer(
        journal,
        "schema=2\n"
        "operation=legacy-migrate\n"
        "transaction=migrate-20260730-000000-1\n"
        "phase=root-renamed\n"
        "committed=false\n",
    )
    public_before = public_state_snapshot(workspace)
    control_before = control_tree_snapshot(workspace.pki)

    result = process_runner(
        [rollover_tools.rollover, "status", "--namespace", workspace.namespace],
        env=isolated_environment,
        timeout=10,
    )

    assert result.status == 2
    assert result.stderr == ""
    assert result.stdout == (
        "status=recovery-required\n"
        "recovery_required=true\n"
        "transaction=migrate-20260730-000000-1\n"
        "operation=legacy-migrate\n"
        "phase=root-renamed\n"
        "terminal_outcome=none\n"
        "required_action=rollback\n"
        "action=run platform-pki-ca-rollover recover --transaction "
        "migrate-20260730-000000-1 --action rollback\n"
    )
    assert public_state_snapshot(workspace) == public_before
    assert control_tree_snapshot(workspace.pki) == control_before


def test_status_rejects_missing_service_issuer(
    rollover_tools,
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    isolated_environment: Mapping[str, str],
    private_text_writer: Callable[[Path, str], None],
    public_state_snapshot: Callable[[RolloverWorkspace], tuple[str, ...]],
    process_runner: Callable[..., ProcessResult],
) -> None:
    workspace = rollover_case_factory("missing-service-issuer")
    (workspace.pki / "state/rollovers").mkdir(mode=0o700)
    for name in ("lifecycle", "root", "intermediate", "inventory", "export"):
        lock = workspace.pki / "locks" / name
        if not lock.exists():
            private_text_writer(lock, "")
    issuer = workspace.pki / "services/app/issuer"
    issuer.unlink()
    workspace.passphrase_file.chmod(0)
    for key in (
        workspace.pki / "authorities/roots/g1/private/root-ca.key",
        workspace.pki
        / "authorities/intermediates/g1-i1/private/intermediate-ca.key",
    ):
        key.chmod(0)
    public_before = public_state_snapshot(workspace)
    controls_before = (
        control_tree_snapshot(workspace.pki / "state"),
        control_tree_snapshot(workspace.pki / "locks"),
    )

    result = process_runner(
        [
            rollover_tools.rollover,
            "status",
            "--namespace",
            workspace.namespace,
            "--format",
            "json",
        ],
        env=isolated_environment,
        timeout=10,
    )

    assert result.status == 1
    assert result.stdout == ""
    assert result.stderr == (
        "[ERROR] Service app issuer manifest is missing or unsafe\n"
    )
    assert not issuer.exists()
    assert public_state_snapshot(workspace) == public_before
    assert (
        control_tree_snapshot(workspace.pki / "state"),
        control_tree_snapshot(workspace.pki / "locks"),
    ) == controls_before
