import json
import stat
from collections.abc import Callable, Mapping
from hashlib import sha256
from pathlib import Path

import pytest

from ..harness import ProcessResult
from .conftest import RolloverTools, RolloverWorkspace


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


def certificate_observables(
    certificate: Path,
    environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> tuple[str, str]:
    fingerprint = process_runner(
        ["openssl", "x509", "-in", certificate, "-noout", "-fingerprint", "-sha256"],
        env=environment,
        timeout=10,
    )
    assert fingerprint.status == 0
    assert fingerprint.stderr == ""
    fingerprint_value = fingerprint.stdout.strip().partition("=")[2].replace(":", "")

    enddate = process_runner(
        ["openssl", "x509", "-in", certificate, "-noout", "-enddate"],
        env=environment,
        timeout=10,
    )
    assert enddate.status == 0
    assert enddate.stderr == ""
    expiry = process_runner(
        [
            "date",
            "-u",
            "-d",
            enddate.stdout.strip().removeprefix("notAfter="),
            "+%Y-%m-%dT%H:%M:%SZ",
        ],
        env=environment,
        timeout=10,
    )
    assert expiry.status == 0
    assert expiry.stderr == ""
    return fingerprint_value, expiry.stdout.strip()


def test_status_rejects_invalid_terminal_marker(
    rollover_tools: RolloverTools,
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
            *rollover_tools.rollover,
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
    rollover_tools: RolloverTools,
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
        [
            *rollover_tools.rollover,
            "status",
            "--namespace",
            workspace.namespace,
        ],
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
        "action=run platform-pki ca-rollover recover --transaction "
        "migrate-20260730-000000-1 --action rollback\n"
    )
    assert public_state_snapshot(workspace) == public_before
    assert control_tree_snapshot(workspace.pki) == control_before


def test_status_rejects_incomplete_committed_migration_journal(
    rollover_tools: RolloverTools,
    rollover_control_workspace_factory: Callable[[str], RolloverWorkspace],
    isolated_environment: Mapping[str, str],
    private_text_writer: Callable[[Path, str], None],
    process_runner: Callable[..., ProcessResult],
) -> None:
    workspace = create_status_control_workspace(
        "incomplete-committed-migration-journal",
        rollover_control_workspace_factory,
        private_text_writer,
    )
    private_text_writer(
        workspace.pki / "state/rollover/journal",
        "schema=2\n"
        "operation=legacy-migrate\n"
        "transaction=migrate-20260730-000000-1\n"
        "phase=complete\n"
        "committed=true\n",
    )

    result = process_runner(
        [
            *rollover_tools.rollover,
            "status",
            "--namespace",
            workspace.namespace,
        ],
        env=isolated_environment,
        timeout=10,
    )

    assert result.status == 1
    assert result.stdout == ""
    assert result.stderr == (
        "[ERROR] PKI recovery journal has invalid recovery state\n"
    )


def test_status_rejects_missing_service_issuer(
    rollover_tools,
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    isolated_environment: Mapping[str, str],
    private_text_writer: Callable[[Path, str], None],
    process_runner: Callable[..., ProcessResult],
) -> None:
    workspace = rollover_case_factory("missing-service-issuer")
    (workspace.pki / "state/rollovers").mkdir(mode=0o700, exist_ok=True)
    for name in ("lifecycle", "root", "intermediate", "inventory", "export"):
        lock = workspace.pki / "locks" / name
        if not lock.exists():
            private_text_writer(lock, "")
    issuer = workspace.pki / "services/app/issuer"
    issuer.unlink()
    restricted = (
        workspace.passphrase_file,
        workspace.pki / "authorities/roots/g1/private/root-ca.key",
        workspace.pki
        / "authorities/intermediates/g1-i1/private/intermediate-ca.key",
    )
    for path in restricted:
        path.chmod(0)
    controls_before = (
        control_tree_snapshot(workspace.pki / "state"),
        control_tree_snapshot(workspace.pki / "locks"),
    )

    result = process_runner(
        [
            *rollover_tools.rollover,
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
    assert (
        control_tree_snapshot(workspace.pki / "state"),
        control_tree_snapshot(workspace.pki / "locks"),
    ) == controls_before
    assert all(stat.S_IMODE(path.stat().st_mode) == 0 for path in restricted)


def test_status_reports_ready_generation(
    rollover_tools,
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    isolated_environment: Mapping[str, str],
    private_text_writer: Callable[[Path, str], None],
    process_runner: Callable[..., ProcessResult],
) -> None:
    workspace = rollover_case_factory("ready-generation")
    (workspace.pki / "state/rollovers").mkdir(mode=0o700, exist_ok=True)
    for name in ("lifecycle", "root", "intermediate", "inventory", "export"):
        lock = workspace.pki / "locks" / name
        if not lock.exists():
            private_text_writer(lock, "")
    restricted = (
        workspace.passphrase_file,
        workspace.pki / "authorities/roots/g1/private/root-ca.key",
        workspace.pki
        / "authorities/intermediates/g1-i1/private/intermediate-ca.key",
    )
    for path in restricted:
        path.chmod(0)

    root_fingerprint, root_expiry = certificate_observables(
        workspace.pki / "authorities/roots/g1/certs/root-ca.crt",
        isolated_environment,
        process_runner,
    )
    intermediate_fingerprint, intermediate_expiry = certificate_observables(
        workspace.pki
        / "authorities/intermediates/g1-i1/certs/intermediate-ca.crt",
        isolated_environment,
        process_runner,
    )
    controls_before = (
        control_tree_snapshot(workspace.pki / "state"),
        control_tree_snapshot(workspace.pki / "locks"),
    )

    result = process_runner(
        [
            *rollover_tools.rollover,
            "status",
            "--namespace",
            workspace.namespace,
            "--format",
            "json",
        ],
        env=isolated_environment,
        timeout=10,
    )

    assert result.status == 0
    assert result.stderr == ""
    assert json.loads(result.stdout) == {
        "schema": 1,
        "status": "ready",
        "recovery_required": False,
        "phase": "idle",
        "active": {
            "root": {
                "generation": "g1",
                "fingerprint_sha256": root_fingerprint,
                "expires_at": root_expiry,
            },
            "intermediate": {
                "generation": "g1-i1",
                "fingerprint_sha256": intermediate_fingerprint,
                "expires_at": intermediate_expiry,
            },
        },
        "candidate": None,
        "retired": [],
        "trust_snapshot_sha256": None,
        "services_on_old_issuer": [],
        "required_action": None,
    }
    assert (
        control_tree_snapshot(workspace.pki / "state"),
        control_tree_snapshot(workspace.pki / "locks"),
    ) == controls_before
    assert all(stat.S_IMODE(path.stat().st_mode) == 0 for path in restricted)
