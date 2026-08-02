import os
import stat
from collections.abc import Callable, Mapping
from hashlib import sha256
from pathlib import Path

import pytest

from ..harness import ProcessResult
from .conftest import RolloverTools, RolloverWorkspace
from .test_ca_rollover_prepare_recovery import _read_strict_record


pytestmark = pytest.mark.pki

MIGRATION_FAILURE_BOUNDARIES = (
    ("after-reservations", "reserved"),
    ("after-root-rename", "root-renamed"),
    ("after-intermediate-rename", "intermediate-renamed"),
    ("after-configs", "configs-published"),
    ("after-issuers", "issuers-published"),
    ("after-quarantine", "quarantined"),
    ("after-active", "active-published"),
)


def _is_sensitive(path: Path, root: Path) -> bool:
    relative = path.relative_to(root)
    return (
        path.name == "passphrase"
        or "private" in relative.parts
        or "operator-private" in relative.parts
        or "quarantine" in relative.parts
        or path.name.endswith((".age", ".tar.gz"))
    )


def _workspace_snapshot(root: Path) -> tuple[str, ...]:
    entries = []
    for path in (root, *sorted(root.rglob("*"))):
        metadata = path.lstat()
        relative = path.relative_to(root).as_posix()
        common = (
            f"{relative}\t{metadata.st_dev}:{metadata.st_ino}"
            f"\t{stat.S_IMODE(metadata.st_mode):o}"
            f"\t{metadata.st_size}\t{metadata.st_mtime_ns}"
        )
        if stat.S_ISDIR(metadata.st_mode):
            detail = "directory"
        elif stat.S_ISREG(metadata.st_mode):
            if _is_sensitive(path, root):
                detail = "redacted"
            else:
                detail = sha256(path.read_bytes()).hexdigest()
        elif stat.S_ISLNK(metadata.st_mode):
            detail = f"symlink:{path.readlink()}"
        else:
            detail = "other"
        entries.append(f"{common}\t{detail}")
    return tuple(entries)


def _migration_command(
    tools: RolloverTools,
    workspace: RolloverWorkspace,
    receipt: Path,
    root_fingerprint: str = "0" * 64,
    intermediate_fingerprint: str = "0" * 64,
) -> list[str | Path]:
    return [
        tools.rollover,
        "migrate",
        "--namespace",
        workspace.namespace,
        "--private-repo",
        workspace.private_repo,
        "--backup-receipt",
        receipt,
        "--yes",
        "--expected-root-sha256",
        root_fingerprint,
        "--expected-intermediate-sha256",
        intermediate_fingerprint,
    ]


def _advance_mtime(path: Path) -> None:
    metadata = path.stat()
    os.utime(
        path,
        ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 1_000_000_000),
        follow_symlinks=False,
    )


def _certificate_fingerprint(
    certificate: Path,
    environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> str:
    result = process_runner(
        [
            "openssl",
            "x509",
            "-in",
            certificate,
            "-noout",
            "-fingerprint",
            "-sha256",
        ],
        env=environment,
        timeout=30,
    )
    assert result.status == 0
    assert result.stderr == ""
    label, separator, value = result.stdout.strip().partition("=")
    assert label == "sha256 Fingerprint"
    assert separator == "="
    fingerprint = value.replace(":", "")
    assert len(fingerprint) == 64
    return fingerprint


@pytest.mark.parametrize("dual_authority", ("root", "intermediate"))
def test_migration_rejects_dual_layout_before_transaction(
    rollover_tools: RolloverTools,
    legacy_rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
    dual_authority: str,
) -> None:
    workspace = legacy_rollover_case_factory(f"migration-dual-{dual_authority}")
    receipt = backup_receipt_factory(workspace)
    if dual_authority == "root":
        generation_path = workspace.pki / "authorities/roots/g1"
    else:
        generation_path = workspace.pki / "authorities/intermediates/g1-i1"
    generation_path.mkdir(mode=0o700)
    before = _workspace_snapshot(workspace.root)

    result = process_runner(
        _migration_command(rollover_tools, workspace, receipt),
        env=isolated_environment,
        timeout=120,
    )

    assert result.status == 1
    assert result.stdout == ""
    assert result.stderr == (
        "[ERROR] Legacy migration refuses incomplete or ambiguous layout: partial\n"
    )
    assert _workspace_snapshot(workspace.root) == before
    assert not tuple((workspace.pki / "state/rollovers").iterdir())


def test_migration_rejects_changed_ca_private_metadata_before_transaction(
    rollover_tools: RolloverTools,
    legacy_rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> None:
    workspace = legacy_rollover_case_factory("migration-changed-ca-private-metadata")
    receipt = backup_receipt_factory(workspace)
    private_key = workspace.pki / "root-ca/private/root-ca.key"
    _advance_mtime(private_key)
    before = _workspace_snapshot(workspace.root)

    result = process_runner(
        _migration_command(rollover_tools, workspace, receipt),
        env=isolated_environment,
        timeout=120,
    )

    assert result.status == 1
    assert result.stdout == ""
    assert result.stderr == (
        "[ERROR] Current private metadata differs from the backed-up state\n"
    )
    assert _workspace_snapshot(workspace.root) == before
    assert not tuple((workspace.pki / "state/rollovers").iterdir())


@pytest.mark.parametrize(
    ("case_name", "private_relative"),
    (
        pytest.param(
            "passphrase",
            "operator-private/secret-passphrase",
            id="passphrase",
        ),
        pytest.param(
            "quarantine",
            "quarantine/private-secret",
            id="quarantine",
        ),
    ),
)
def test_migration_rejects_changed_additional_private_metadata_before_transaction(
    rollover_tools: RolloverTools,
    legacy_rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    private_text_writer: Callable[[Path, str], None],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
    case_name: str,
    private_relative: str,
) -> None:
    workspace = legacy_rollover_case_factory(
        f"migration-changed-additional-private-{case_name}"
    )
    private_file = workspace.pki / private_relative
    private_text_writer(private_file, "private-sentinel\n")
    receipt = backup_receipt_factory(workspace)
    _advance_mtime(private_file)
    before = _workspace_snapshot(workspace.root)

    result = process_runner(
        _migration_command(rollover_tools, workspace, receipt),
        env=isolated_environment,
        timeout=120,
    )

    assert result.status == 1
    assert result.stdout == ""
    assert result.stderr == (
        "[ERROR] Current private metadata differs from the backed-up state\n"
    )
    assert _workspace_snapshot(workspace.root) == before
    assert not tuple((workspace.pki / "state/rollovers").iterdir())


def test_migration_rejects_extra_service_directory_before_transaction(
    rollover_tools: RolloverTools,
    legacy_rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> None:
    workspace = legacy_rollover_case_factory("migration-extra-service-directory")
    (workspace.pki / "services/not-in-inventory").mkdir(mode=0o700)
    receipt = backup_receipt_factory(workspace)
    root_fingerprint = _certificate_fingerprint(
        workspace.pki / "root-ca/certs/root-ca.crt",
        isolated_environment,
        process_runner,
    )
    intermediate_fingerprint = _certificate_fingerprint(
        workspace.pki / "intermediate-ca/certs/intermediate-ca.crt",
        isolated_environment,
        process_runner,
    )
    before = _workspace_snapshot(workspace.root)

    result = process_runner(
        _migration_command(
            rollover_tools,
            workspace,
            receipt,
            root_fingerprint,
            intermediate_fingerprint,
        ),
        env=isolated_environment,
        timeout=120,
    )

    assert result.status == 1
    assert result.stdout == ""
    assert result.stderr == (
        "[ERROR] Legacy service directory is absent from inventory: "
        "not-in-inventory\n"
    )
    assert _workspace_snapshot(workspace.root) == before
    assert not tuple((workspace.pki / "state/rollovers").iterdir())
    assert not tuple(Path(isolated_environment["TMPDIR"]).iterdir())


def test_migration_rejects_replaced_transaction_evidence(
    rollover_tools: RolloverTools,
    legacy_rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> None:
    workspace = legacy_rollover_case_factory(
        "migration-replaced-transaction-evidence"
    )
    receipt = backup_receipt_factory(workspace)
    root_fingerprint = _certificate_fingerprint(
        workspace.pki / "root-ca/certs/root-ca.crt",
        isolated_environment,
        process_runner,
    )
    intermediate_fingerprint = _certificate_fingerprint(
        workspace.pki / "intermediate-ca/certs/intermediate-ca.crt",
        isolated_environment,
        process_runner,
    )
    failure_environment = dict(isolated_environment)
    failure_environment["PLATFORM_PKI_MIGRATE_FAIL_AT"] = "after-reservations"

    migration = process_runner(
        _migration_command(
            rollover_tools,
            workspace,
            receipt,
            root_fingerprint,
            intermediate_fingerprint,
        ),
        env=failure_environment,
        timeout=120,
    )
    assert migration.status == 1
    assert migration.stdout == ""
    assert migration.stderr == (
        "[ERROR] Injected migration interruption at after-reservations\n"
    )

    journal = (workspace.pki / "state/rollover/journal").read_text()
    transactions = [
        line.removeprefix("transaction=")
        for line in journal.splitlines()
        if line.startswith("transaction=")
    ]
    assert len(transactions) == 1
    transaction = transactions[0]
    assert transaction.startswith("migrate-")
    services = workspace.pki / "state/rollover" / transaction / "services"
    assert services.read_text() == "app\n"
    with services.open("a", encoding="ascii") as stream:
        stream.write("foreign\n")
    before = _workspace_snapshot(workspace.root)

    result = process_runner(
        [
            rollover_tools.rollover,
            "recover",
            "--namespace",
            workspace.namespace,
            "--transaction",
            transaction,
            "--action",
            "rollback",
            "--yes",
        ],
        env=isolated_environment,
        timeout=120,
    )

    assert result.status == 1
    assert result.stdout == ""
    assert result.stderr == "[ERROR] Recovery service set changed\n"
    assert services.read_text() == "app\nforeign\n"
    assert _workspace_snapshot(workspace.root) == before
    assert not tuple(Path(isolated_environment["TMPDIR"]).iterdir())


@pytest.mark.parametrize(
    ("boundary", "phase"),
    MIGRATION_FAILURE_BOUNDARIES,
    ids=[boundary for boundary, _ in MIGRATION_FAILURE_BOUNDARIES],
)
def test_migration_failure_boundary_rollback(
    rollover_tools: RolloverTools,
    legacy_rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
    boundary: str,
    phase: str,
) -> None:
    workspace = legacy_rollover_case_factory(
        f"migration-failure-boundary-rollback-{boundary}"
    )
    receipt = backup_receipt_factory(workspace)
    legacy_root = workspace.pki / "root-ca"
    legacy_intermediate = workspace.pki / "intermediate-ca"
    root_source_identity = (
        f"{legacy_root.stat().st_dev}:{legacy_root.stat().st_ino}"
    )
    intermediate_source_identity = (
        f"{legacy_intermediate.stat().st_dev}:"
        f"{legacy_intermediate.stat().st_ino}"
    )
    root_key = legacy_root / "private/root-ca.key"
    intermediate_key = legacy_intermediate / "private/intermediate-ca.key"
    root_key_identity = (root_key.stat().st_dev, root_key.stat().st_ino)
    intermediate_key_identity = (
        intermediate_key.stat().st_dev,
        intermediate_key.stat().st_ino,
    )
    backup_before = _workspace_snapshot(workspace.root / "backups")
    root_fingerprint = _certificate_fingerprint(
        legacy_root / "certs/root-ca.crt",
        isolated_environment,
        process_runner,
    )
    intermediate_fingerprint = _certificate_fingerprint(
        legacy_intermediate / "certs/intermediate-ca.crt",
        isolated_environment,
        process_runner,
    )
    failure_environment = dict(isolated_environment)
    failure_environment["PLATFORM_PKI_MIGRATE_FAIL_AT"] = boundary

    migration = process_runner(
        _migration_command(
            rollover_tools,
            workspace,
            receipt,
            root_fingerprint,
            intermediate_fingerprint,
        ),
        env=failure_environment,
        timeout=120,
    )
    assert migration.status == 1
    assert migration.stdout == ""
    assert migration.stderr == (
        f"[ERROR] Injected migration interruption at {boundary}\n"
    )

    journal_path = workspace.pki / "state/rollover/journal"
    journal = _read_strict_record(journal_path)
    transaction = journal["transaction"]
    assert transaction.startswith("migrate-")
    assert journal["schema"] == "2"
    assert journal["operation"] == "legacy-migrate"
    assert journal["phase"] == phase
    assert journal["committed"] == "false"

    status = process_runner(
        [
            rollover_tools.rollover,
            "status",
            "--namespace",
            workspace.namespace,
        ],
        env=isolated_environment,
        timeout=30,
    )
    assert status.status == 2
    assert status.stderr == ""
    assert status.stdout == (
        "status=recovery-required\n"
        "recovery_required=true\n"
        f"transaction={transaction}\n"
        "operation=legacy-migrate\n"
        f"phase={phase}\n"
        "terminal_outcome=none\n"
        "required_action=rollback\n"
        "action=run platform-pki-ca-rollover recover --transaction "
        f"{transaction} --action rollback\n"
    )

    recovery = process_runner(
        [
            rollover_tools.rollover,
            "recover",
            "--namespace",
            workspace.namespace,
            "--transaction",
            transaction,
            "--action",
            "rollback",
            "--yes",
        ],
        env=isolated_environment,
        timeout=120,
    )
    assert recovery.status == 0
    assert recovery.stdout == (
        f"[OK] Rolled back migration transaction: {transaction}\n"
    )
    assert recovery.stderr == ""

    final_journal = _read_strict_record(journal_path)
    assert final_journal["operation"] == "legacy-migrate"
    assert final_journal["transaction"] == transaction
    assert final_journal["phase"] == "rolled-back"
    assert final_journal["committed"] == "true"
    assert final_journal["recovery_action"] == "rollback"
    assert final_journal["recovery_step"] == "rollback-provenance-done"
    assert legacy_root.is_dir() and not legacy_root.is_symlink()
    assert legacy_intermediate.is_dir() and not legacy_intermediate.is_symlink()
    assert not (workspace.pki / "authorities/roots/g1").exists()
    assert not (workspace.pki / "authorities/intermediates/g1-i1").exists()
    assert not (workspace.pki / "state/active-issuer").exists()
    assert not (workspace.pki / "services/app/issuer").exists()
    assert not (workspace.pki / "state/rollover/recovery-required").exists()

    root_reservation = _read_strict_record(
        workspace.pki / "state/generation-reservations/g1"
    )
    assert root_reservation == {
        "generation": "g1",
        "kind": "root",
        "status": "abandoned",
        "fingerprint_sha256": root_fingerprint,
        "source_identity": root_source_identity,
    }
    intermediate_reservation = _read_strict_record(
        workspace.pki / "state/generation-reservations/g1-i1"
    )
    assert intermediate_reservation == {
        "generation": "g1-i1",
        "kind": "intermediate",
        "status": "abandoned",
        "fingerprint_sha256": intermediate_fingerprint,
        "source_identity": intermediate_source_identity,
    }
    assert not tuple((workspace.pki / "state/rollover").glob("backup-session-*"))
    assert _workspace_snapshot(workspace.root / "backups") == backup_before
    provenance_stage = workspace.pki / "legacy" / f".{transaction}.publish"
    provenance = workspace.pki / "legacy" / transaction
    assert not provenance_stage.exists() and not provenance_stage.is_symlink()
    assert not provenance.exists() and not provenance.is_symlink()
    transaction_directory = workspace.pki / "state/rollover" / transaction
    assert transaction_directory.is_dir() and not transaction_directory.is_symlink()
    assert (root_key.stat().st_dev, root_key.stat().st_ino) == root_key_identity
    assert (
        intermediate_key.stat().st_dev,
        intermediate_key.stat().st_ino,
    ) == intermediate_key_identity
    assert not tuple(Path(isolated_environment["TMPDIR"]).iterdir())


def test_migration_success_preserves_private_key_identities(
    rollover_tools: RolloverTools,
    legacy_rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> None:
    workspace = legacy_rollover_case_factory("migration-success")
    receipt = backup_receipt_factory(workspace)
    legacy_root = workspace.pki / "root-ca"
    legacy_intermediate = workspace.pki / "intermediate-ca"
    root_key = legacy_root / "private/root-ca.key"
    intermediate_key = legacy_intermediate / "private/intermediate-ca.key"
    root_key_identity = (root_key.stat().st_dev, root_key.stat().st_ino)
    intermediate_key_identity = (
        intermediate_key.stat().st_dev,
        intermediate_key.stat().st_ino,
    )
    root_fingerprint = _certificate_fingerprint(
        legacy_root / "certs/root-ca.crt",
        isolated_environment,
        process_runner,
    )
    intermediate_fingerprint = _certificate_fingerprint(
        legacy_intermediate / "certs/intermediate-ca.crt",
        isolated_environment,
        process_runner,
    )

    result = process_runner(
        _migration_command(
            rollover_tools,
            workspace,
            receipt,
            root_fingerprint,
            intermediate_fingerprint,
        ),
        env=isolated_environment,
        timeout=120,
    )

    generation_root = workspace.pki / "authorities/roots/g1"
    generation_intermediate = workspace.pki / "authorities/intermediates/g1-i1"
    migrated_root_key = generation_root / "private/root-ca.key"
    migrated_intermediate_key = (
        generation_intermediate / "private/intermediate-ca.key"
    )
    assert result.status == 0, result
    assert result.stdout == (
        "[OK] Migrated legacy PKI state to root g1 and intermediate g1-i1\n"
    )
    assert result.stderr == ""
    assert not legacy_root.exists()
    assert not legacy_intermediate.exists()
    assert (migrated_root_key.stat().st_dev, migrated_root_key.stat().st_ino) == (
        root_key_identity
    )
    assert (
        migrated_intermediate_key.stat().st_dev,
        migrated_intermediate_key.stat().st_ino,
    ) == intermediate_key_identity
    assert (workspace.pki / "state/active-issuer").read_text() == (
        "root=g1\nintermediate=g1-i1\n"
    )
    assert (workspace.pki / "services/app/issuer").read_text() == (
        "root=g1\nintermediate=g1-i1\n"
    )
    journal = (workspace.pki / "state/rollover/journal").read_text()
    assert "operation=legacy-migrate\n" in journal
    assert "phase=complete\n" in journal
    assert journal.endswith("committed=true\n")
    transaction = next(
        line.removeprefix("transaction=")
        for line in journal.splitlines()
        if line.startswith("transaction=")
    )
    assert transaction.startswith("migrate-")
    assert not (workspace.pki / "state/rollover/recovery-required").exists()
    assert not (workspace.pki / "state/rollover" / transaction).exists()
    assert not tuple(Path(isolated_environment["TMPDIR"]).iterdir())


def test_completed_migration_is_idempotent(
    rollover_tools: RolloverTools,
    legacy_rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> None:
    workspace = legacy_rollover_case_factory("migration-idempotence")
    receipt = backup_receipt_factory(workspace)
    root_fingerprint = _certificate_fingerprint(
        workspace.pki / "root-ca/certs/root-ca.crt",
        isolated_environment,
        process_runner,
    )
    intermediate_fingerprint = _certificate_fingerprint(
        workspace.pki / "intermediate-ca/certs/intermediate-ca.crt",
        isolated_environment,
        process_runner,
    )
    command = _migration_command(
        rollover_tools,
        workspace,
        receipt,
        root_fingerprint,
        intermediate_fingerprint,
    )
    first_result = process_runner(
        command,
        env=isolated_environment,
        timeout=120,
    )
    assert first_result.status == 0, first_result
    before = _workspace_snapshot(workspace.root)

    result = process_runner(
        command,
        env=isolated_environment,
        timeout=120,
    )

    assert result.status == 0
    assert result.stdout == (
        "[OK] Legacy PKI migration is already complete; no changes made\n"
    )
    assert result.stderr == ""
    assert _workspace_snapshot(workspace.root) == before
    assert not tuple(Path(isolated_environment["TMPDIR"]).iterdir())
