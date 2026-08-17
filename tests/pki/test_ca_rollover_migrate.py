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

MIGRATION_PHASES = {
    "after-journal": "pre-mutation",
    **dict(MIGRATION_FAILURE_BOUNDARIES),
}

MIGRATION_ROLLBACK_RECOVERY_BOUNDARIES = (
    "rollback-active",
    "rollback-issuer-app",
    "rollback-quarantine-pki.env",
    "rollback-config-root",
    "rollback-config-intermediate",
    "rollback-intermediate-rename",
    "rollback-root-rename",
    "rollback-reservation-root",
    "rollback-reservation-intermediate",
    "rollback-backup-session",
    "rollback-provenance",
)

MIGRATION_RESUME_RECOVERY_BOUNDARIES = (
    "resume-backup-session",
    "resume-reservation-root",
    "resume-reservation-intermediate",
    "resume-root-rename",
    "resume-intermediate-rename",
    "resume-config-root",
    "resume-config-intermediate",
    "resume-issuer-app",
    "resume-quarantine-pki.env",
    "resume-consume-root",
    "resume-consume-intermediate",
    "resume-active",
    "resume-provenance",
)

MIGRATION_HOSTILE_FILE_CASES = (
    (
        "backup-session",
        "after-reservations",
        "backup_session",
        "Backup session record is not in a journaled identity state",
    ),
    (
        "root-reservation",
        "after-reservations",
        "root_reservation",
        "Root reservation is not in a journaled identity state",
    ),
    (
        "intermediate-reservation",
        "after-reservations",
        "intermediate_reservation",
        "Intermediate reservation is not in a journaled identity state",
    ),
    (
        "root-config-original",
        "after-reservations",
        "legacy_root_config",
        "Root OpenSSL configuration is not in a journaled identity state",
    ),
    (
        "root-config-published",
        "after-configs",
        "generation_root_config",
        "Root OpenSSL configuration is not in a journaled identity state",
    ),
    (
        "intermediate-config-published",
        "after-configs",
        "generation_intermediate_config",
        "Intermediate OpenSSL configuration is not in a journaled identity state",
    ),
    (
        "issuer",
        "after-issuers",
        "service_issuer",
        "Service app issuer is not in a journaled identity state",
    ),
    (
        "quarantine",
        "after-quarantine",
        "quarantine_pki_env",
        "Quarantine entry is ambiguous or replaced: pki.env",
    ),
    (
        "active",
        "after-active",
        "active_issuer",
        "Active issuer manifest is not in a journaled identity state",
    ),
)

MIGRATION_DUAL_DIRECTORY_CASES = (
    (
        "root",
        "after-root-rename",
        "root-ca",
        "authorities/roots/g1",
    ),
    (
        "intermediate",
        "after-intermediate-rename",
        "intermediate-ca",
        "authorities/intermediates/g1-i1",
    ),
)


def _is_sensitive(path: Path, root: Path) -> bool:
    relative = path.relative_to(root)
    return (
        path.name in {"passphrase", "pki.env"}
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


def _metadata_tree(root: Path) -> tuple[str, ...]:
    entries = []
    for path in sorted(root.rglob("*")):
        metadata = path.lstat()
        entries.append(
            f"{path.relative_to(root).as_posix()}\t"
            f"{stat.S_IFMT(metadata.st_mode):o}\t"
            f"{metadata.st_dev}:{metadata.st_ino}\t"
            f"{stat.S_IMODE(metadata.st_mode):o}\t"
            f"{metadata.st_size}\t{metadata.st_mtime_ns}"
        )
    return tuple(entries)


def _migration_command(
    tools: RolloverTools,
    workspace: RolloverWorkspace,
    receipt: Path,
    root_fingerprint: str = "0" * 64,
    intermediate_fingerprint: str = "0" * 64,
) -> list[str | Path]:
    return [
        *tools.rollover,
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


def _migration_inputs(
    tools: RolloverTools,
    workspace: RolloverWorkspace,
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> tuple[list[str | Path], str, str]:
    receipt = backup_receipt_factory(workspace)
    root_fingerprint = _certificate_fingerprint(
        workspace.pki / "root-ca/certs/root-ca.crt",
        environment,
        process_runner,
    )
    intermediate_fingerprint = _certificate_fingerprint(
        workspace.pki / "intermediate-ca/certs/intermediate-ca.crt",
        environment,
        process_runner,
    )
    return (
        _migration_command(
            tools,
            workspace,
            receipt,
            root_fingerprint,
            intermediate_fingerprint,
        ),
        root_fingerprint,
        intermediate_fingerprint,
    )


def _recovery_command(
    tools: RolloverTools,
    workspace: RolloverWorkspace,
    transaction: str,
    action: str,
) -> list[str | Path]:
    return [
        *tools.rollover,
        "recover",
        "--namespace",
        workspace.namespace,
        "--transaction",
        transaction,
        "--action",
        action,
        "--yes",
    ]


def _crash_migration(
    command: list[str | Path],
    workspace: RolloverWorkspace,
    boundary: str,
    environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> dict[str, str]:
    crash_environment = dict(environment)
    crash_environment["PLATFORM_PKI_MIGRATE_CRASH_AT"] = boundary
    result = process_runner(command, env=crash_environment, timeout=120)
    assert result.status == 137
    assert result.stdout == ""
    assert result.stderr == ""
    journal = _read_strict_record(workspace.pki / "state/rollover/journal")
    assert journal["schema"] == "2"
    assert journal["operation"] == "legacy-migrate"
    assert journal["transaction"].startswith("migrate-")
    assert journal["phase"] == MIGRATION_PHASES[boundary]
    assert journal["committed"] == "false"
    return journal


def _crash_migration_recovery(
    tools: RolloverTools,
    workspace: RolloverWorkspace,
    transaction: str,
    action: str,
    checkpoint: str,
    environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> dict[str, str]:
    crash_environment = dict(environment)
    crash_environment["PLATFORM_PKI_RECOVER_CRASH_AT"] = checkpoint
    result = process_runner(
        _recovery_command(tools, workspace, transaction, action),
        env=crash_environment,
        timeout=120,
    )
    assert result.status == 137
    assert result.stdout == ""
    assert result.stderr == ""
    journal = _read_strict_record(workspace.pki / "state/rollover/journal")
    assert journal["schema"] == "2"
    assert journal["operation"] == "legacy-migrate"
    assert journal["transaction"] == transaction
    assert journal["phase"] == "recovering"
    assert journal["committed"] == "false"
    assert journal["recovery_action"] == action
    assert journal["recovery_step"] == checkpoint
    return journal


def _hostile_migration_path(
    workspace: RolloverWorkspace,
    journal: Mapping[str, str],
    role: str,
) -> Path:
    transaction = journal["transaction"]
    paths = {
        "backup_session": Path(journal["backup_session"]),
        "root_reservation": workspace.pki / "state/generation-reservations/g1",
        "intermediate_reservation": (
            workspace.pki / "state/generation-reservations/g1-i1"
        ),
        "legacy_root_config": workspace.pki / "root-ca/openssl.cnf",
        "generation_root_config": (
            workspace.pki / "authorities/roots/g1/openssl.cnf"
        ),
        "generation_intermediate_config": (
            workspace.pki / "authorities/intermediates/g1-i1/openssl.cnf"
        ),
        "service_issuer": workspace.pki / "services/app/issuer",
        "quarantine_pki_env": (
            workspace.pki
            / "state/rollover"
            / transaction
            / "quarantine/pki.env"
        ),
        "active_issuer": workspace.pki / "state/active-issuer",
    }
    return paths[role]


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
            *rollover_tools.rollover,
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
            *rollover_tools.rollover,
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
        "action=run platform-pki ca-rollover recover --transaction "
        f"{transaction} --action rollback\n"
    )

    recovery = process_runner(
        [
            *rollover_tools.rollover,
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


@pytest.mark.parametrize(
    ("boundary", "phase"),
    MIGRATION_FAILURE_BOUNDARIES,
    ids=[boundary for boundary, _ in MIGRATION_FAILURE_BOUNDARIES],
)
def test_migration_failure_boundary_resume(
    rollover_tools: RolloverTools,
    legacy_rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
    boundary: str,
    phase: str,
) -> None:
    workspace = legacy_rollover_case_factory(
        f"migration-failure-boundary-resume-{boundary}"
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
    root_key_metadata = root_key.lstat()
    intermediate_key_metadata = intermediate_key.lstat()
    assert stat.S_ISREG(root_key_metadata.st_mode) and not root_key.is_symlink()
    assert stat.S_ISREG(intermediate_key_metadata.st_mode) and not intermediate_key.is_symlink()
    root_key_identity = (root_key_metadata.st_dev, root_key_metadata.st_ino)
    intermediate_key_identity = (
        intermediate_key_metadata.st_dev,
        intermediate_key_metadata.st_ino,
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
            *rollover_tools.rollover,
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
        "action=run platform-pki ca-rollover recover --transaction "
        f"{transaction} --action rollback\n"
    )

    recovery = process_runner(
        [
            *rollover_tools.rollover,
            "recover",
            "--namespace",
            workspace.namespace,
            "--transaction",
            transaction,
            "--action",
            "resume",
            "--yes",
        ],
        env=isolated_environment,
        timeout=120,
    )
    assert recovery.status == 0
    assert recovery.stdout == (
        f"[OK] Resumed migration transaction: {transaction}\n"
    )
    assert recovery.stderr == ""

    final_journal = _read_strict_record(journal_path)
    assert final_journal["schema"] == "2"
    assert final_journal["operation"] == "legacy-migrate"
    assert final_journal["transaction"] == transaction
    assert final_journal["phase"] == "complete"
    assert final_journal["committed"] == "true"
    assert final_journal["recovery_action"] == "resume"
    assert final_journal["recovery_step"] == "resume-provenance-done"
    generation_root = workspace.pki / "authorities/roots/g1"
    generation_intermediate = workspace.pki / "authorities/intermediates/g1-i1"
    assert not legacy_root.exists() and not legacy_root.is_symlink()
    assert not legacy_intermediate.exists() and not legacy_intermediate.is_symlink()
    assert generation_root.is_dir() and not generation_root.is_symlink()
    assert generation_intermediate.is_dir() and not generation_intermediate.is_symlink()
    expected_issuer = "root=g1\nintermediate=g1-i1\n"
    active_issuer = workspace.pki / "state/active-issuer"
    service_issuer = workspace.pki / "services/app/issuer"
    assert active_issuer.is_file() and not active_issuer.is_symlink()
    assert service_issuer.is_file() and not service_issuer.is_symlink()
    assert active_issuer.read_text() == expected_issuer
    assert service_issuer.read_text() == expected_issuer
    recovery_marker = workspace.pki / "state/rollover/recovery-required"
    assert not recovery_marker.exists() and not recovery_marker.is_symlink()

    root_reservation = _read_strict_record(
        workspace.pki / "state/generation-reservations/g1"
    )
    assert root_reservation == {
        "generation": "g1",
        "kind": "root",
        "status": "consumed",
        "fingerprint_sha256": root_fingerprint,
        "source_identity": root_source_identity,
    }
    intermediate_reservation = _read_strict_record(
        workspace.pki / "state/generation-reservations/g1-i1"
    )
    assert intermediate_reservation == {
        "generation": "g1-i1",
        "kind": "intermediate",
        "status": "consumed",
        "fingerprint_sha256": intermediate_fingerprint,
        "source_identity": intermediate_source_identity,
    }
    backup_sessions = tuple(
        (workspace.pki / "state/rollover").glob("backup-session-*")
    )
    assert len(backup_sessions) == 1
    assert backup_sessions[0].is_file() and not backup_sessions[0].is_symlink()
    backup_session_metadata = backup_sessions[0].lstat()
    assert stat.S_IMODE(backup_session_metadata.st_mode) == 0o600
    assert journal["backup_session"] == str(backup_sessions[0])
    assert journal["backup_session_published_identity"] == (
        f"{backup_session_metadata.st_dev}:{backup_session_metadata.st_ino}:"
        f"{backup_session_metadata.st_uid}:"
        f"{stat.S_IMODE(backup_session_metadata.st_mode):o}:"
        f"{backup_session_metadata.st_nlink}:{backup_session_metadata.st_size}:"
        "regular file"
    )
    assert _workspace_snapshot(workspace.root / "backups") == backup_before
    provenance_stage = workspace.pki / "legacy" / f".{transaction}.publish"
    provenance = workspace.pki / "legacy" / transaction
    assert not provenance_stage.exists() and not provenance_stage.is_symlink()
    assert provenance.is_dir() and not provenance.is_symlink()
    provenance_metadata = provenance.lstat()
    assert journal["provenance_dir"] == str(provenance)
    assert journal["provenance_identity"] == (
        f"{provenance_metadata.st_dev}:{provenance_metadata.st_ino}:"
        f"{provenance_metadata.st_uid}:"
        f"{stat.S_IMODE(provenance_metadata.st_mode):o}:directory"
    )
    transaction_directory = workspace.pki / "state/rollover" / transaction
    assert not transaction_directory.exists() and not transaction_directory.is_symlink()
    migrated_root_key = generation_root / "private/root-ca.key"
    migrated_intermediate_key = (
        generation_intermediate / "private/intermediate-ca.key"
    )
    migrated_root_key_metadata = migrated_root_key.lstat()
    migrated_intermediate_key_metadata = migrated_intermediate_key.lstat()
    assert stat.S_ISREG(migrated_root_key_metadata.st_mode)
    assert stat.S_ISREG(migrated_intermediate_key_metadata.st_mode)
    assert not migrated_root_key.is_symlink()
    assert not migrated_intermediate_key.is_symlink()
    assert (
        migrated_root_key_metadata.st_dev,
        migrated_root_key_metadata.st_ino,
    ) == root_key_identity
    assert (
        migrated_intermediate_key_metadata.st_dev,
        migrated_intermediate_key_metadata.st_ino,
    ) == intermediate_key_identity
    assert not tuple(Path(isolated_environment["TMPDIR"]).iterdir())


def test_migration_unresolved_recovery_state(
    rollover_tools: RolloverTools,
    legacy_rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> None:
    workspace = legacy_rollover_case_factory("migration-unresolved-recovery")
    command, _, _ = _migration_inputs(
        rollover_tools,
        workspace,
        backup_receipt_factory,
        isolated_environment,
        process_runner,
    )
    failure_environment = dict(isolated_environment)
    failure_environment["PLATFORM_PKI_MIGRATE_FAIL_AT"] = "after-reservations"

    migration = process_runner(
        command,
        env=failure_environment,
        timeout=120,
    )
    assert migration.status == 1
    assert migration.stdout == ""
    assert migration.stderr == (
        "[ERROR] Injected migration interruption at after-reservations\n"
    )
    journal_path = workspace.pki / "state/rollover/journal"
    journal = _read_strict_record(journal_path)
    transaction = journal["transaction"]
    assert journal["phase"] == "reserved"
    assert journal["committed"] == "false"
    marker = workspace.pki / "state/rollover/recovery-required"
    assert _read_strict_record(marker) == {
        "transaction": transaction,
        "action": "run platform-pki-ca-rollover recover",
    }

    status = process_runner(
        [
            *rollover_tools.rollover,
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
        "phase=reserved\n"
        "terminal_outcome=none\n"
        "required_action=rollback\n"
        "action=run platform-pki ca-rollover recover --transaction "
        f"{transaction} --action rollback\n"
    )
    recovery = process_runner(
        _recovery_command(rollover_tools, workspace, transaction, "rollback"),
        env=isolated_environment,
        timeout=120,
    )
    assert recovery.status == 0
    assert recovery.stdout == (
        f"[OK] Rolled back migration transaction: {transaction}\n"
    )
    assert recovery.stderr == ""
    final_journal = _read_strict_record(journal_path)
    assert final_journal["phase"] == "rolled-back"
    assert final_journal["committed"] == "true"
    assert not marker.exists() and not marker.is_symlink()
    assert (workspace.pki / "root-ca").is_dir()
    assert (workspace.pki / "intermediate-ca").is_dir()
    assert not tuple(Path(isolated_environment["TMPDIR"]).iterdir())


@pytest.mark.parametrize("category", ("manifest", "readme", "quarantine"))
def test_migration_rejects_tampered_provenance(
    rollover_tools: RolloverTools,
    legacy_rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    private_text_writer: Callable[[Path, str], None],
    process_runner: Callable[..., ProcessResult],
    category: str,
) -> None:
    workspace = legacy_rollover_case_factory(
        f"migration-tampered-provenance-{category}"
    )
    private_text_writer(workspace.pki / "pki.env", "private-sentinel\n")
    command, _, _ = _migration_inputs(
        rollover_tools,
        workspace,
        backup_receipt_factory,
        isolated_environment,
        process_runner,
    )
    journal = _crash_migration(
        command,
        workspace,
        "after-journal",
        isolated_environment,
        process_runner,
    )
    temporary_after_crash = _metadata_tree(Path(isolated_environment["TMPDIR"]))
    transaction = journal["transaction"]
    provenance = Path(journal["provenance_stage"])
    assert provenance == workspace.pki / "legacy" / f".{transaction}.publish"
    manifest = provenance / "provenance-manifest"
    quarantine = provenance / "quarantine/pki.env"
    manifest_rows = [line.split("|") for line in manifest.read_text().splitlines()]
    quarantine_rows = [row for row in manifest_rows if row[1] == "quarantine/pki.env"]
    assert len(quarantine_rows) == 1
    assert quarantine_rows[0][0] == "regular file"
    assert quarantine_rows[0][3] == "secret"
    hostile = {
        "manifest": manifest,
        "readme": provenance / "README",
        "quarantine": quarantine,
    }[category]
    with hostile.open("a") as stream:
        stream.write("tampered\n")
    before = _workspace_snapshot(workspace.root)

    recovery = process_runner(
        _recovery_command(rollover_tools, workspace, transaction, "resume"),
        env=isolated_environment,
        timeout=120,
    )
    assert recovery.status == 1
    assert recovery.stdout == ""
    if category == "manifest":
        assert "Migration provenance manifest identity changed" in recovery.stderr
    else:
        assert recovery.stderr == (
            "[ERROR] Migration provenance contents do not match their manifest\n"
        )
    assert _workspace_snapshot(workspace.root) == before
    assert _metadata_tree(Path(isolated_environment["TMPDIR"])) == temporary_after_crash


def test_migration_rollback_recovery_checkpoints(
    rollover_tools: RolloverTools,
    legacy_rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    private_text_writer: Callable[[Path, str], None],
    process_runner: Callable[..., ProcessResult],
) -> None:
    workspace = legacy_rollover_case_factory("migration-rollback-checkpoints")
    private_text_writer(workspace.pki / "pki.env", "legacy-config\n")
    legacy_root_key = workspace.pki / "root-ca/private/root-ca.key"
    legacy_intermediate_key = (
        workspace.pki / "intermediate-ca/private/intermediate-ca.key"
    )
    root_key_identity = (
        legacy_root_key.lstat().st_dev,
        legacy_root_key.lstat().st_ino,
    )
    intermediate_key_identity = (
        legacy_intermediate_key.lstat().st_dev,
        legacy_intermediate_key.lstat().st_ino,
    )
    command, _, _ = _migration_inputs(
        rollover_tools,
        workspace,
        backup_receipt_factory,
        isolated_environment,
        process_runner,
    )
    journal = _crash_migration(
        command,
        workspace,
        "after-active",
        isolated_environment,
        process_runner,
    )
    temporary_after_crash = _metadata_tree(Path(isolated_environment["TMPDIR"]))
    transaction = journal["transaction"]
    for boundary in MIGRATION_ROLLBACK_RECOVERY_BOUNDARIES:
        for suffix in ("pending", "done"):
            _crash_migration_recovery(
                rollover_tools,
                workspace,
                transaction,
                "rollback",
                f"{boundary}-{suffix}",
                isolated_environment,
                process_runner,
            )

    recovery = process_runner(
        _recovery_command(rollover_tools, workspace, transaction, "rollback"),
        env=isolated_environment,
        timeout=120,
    )
    assert recovery.status == 0
    assert recovery.stdout == (
        f"[OK] Rolled back migration transaction: {transaction}\n"
    )
    assert recovery.stderr == ""
    final_journal = _read_strict_record(workspace.pki / "state/rollover/journal")
    assert final_journal["phase"] == "rolled-back"
    assert final_journal["committed"] == "true"
    assert final_journal["recovery_action"] == "rollback"
    assert final_journal["recovery_step"] == "rollback-provenance-done"
    assert (workspace.pki / "pki.env").read_text() == "legacy-config\n"
    assert not (workspace.pki / "authorities/roots/g1").exists()
    assert not (workspace.pki / "authorities/intermediates/g1-i1").exists()
    assert not (workspace.pki / "legacy" / transaction).exists()
    assert not (workspace.pki / "legacy" / f".{transaction}.publish").exists()
    assert (
        legacy_root_key.lstat().st_dev,
        legacy_root_key.lstat().st_ino,
    ) == root_key_identity
    assert (
        legacy_intermediate_key.lstat().st_dev,
        legacy_intermediate_key.lstat().st_ino,
    ) == intermediate_key_identity
    assert not tuple((workspace.pki / "state/rollover").glob("backup-session-*"))
    assert _metadata_tree(Path(isolated_environment["TMPDIR"])) == temporary_after_crash


def test_migration_resume_recovery_checkpoints(
    rollover_tools: RolloverTools,
    legacy_rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    private_text_writer: Callable[[Path, str], None],
    process_runner: Callable[..., ProcessResult],
) -> None:
    workspace = legacy_rollover_case_factory("migration-resume-checkpoints")
    private_text_writer(workspace.pki / "pki.env", "legacy-config\n")
    legacy_root_key = workspace.pki / "root-ca/private/root-ca.key"
    legacy_intermediate_key = (
        workspace.pki / "intermediate-ca/private/intermediate-ca.key"
    )
    root_key_identity = (
        legacy_root_key.lstat().st_dev,
        legacy_root_key.lstat().st_ino,
    )
    intermediate_key_identity = (
        legacy_intermediate_key.lstat().st_dev,
        legacy_intermediate_key.lstat().st_ino,
    )
    command, _, _ = _migration_inputs(
        rollover_tools,
        workspace,
        backup_receipt_factory,
        isolated_environment,
        process_runner,
    )
    journal = _crash_migration(
        command,
        workspace,
        "after-journal",
        isolated_environment,
        process_runner,
    )
    temporary_after_crash = _metadata_tree(Path(isolated_environment["TMPDIR"]))
    transaction = journal["transaction"]
    for boundary in MIGRATION_RESUME_RECOVERY_BOUNDARIES:
        for suffix in ("pending", "done"):
            _crash_migration_recovery(
                rollover_tools,
                workspace,
                transaction,
                "resume",
                f"{boundary}-{suffix}",
                isolated_environment,
                process_runner,
            )

    recovery = process_runner(
        _recovery_command(rollover_tools, workspace, transaction, "resume"),
        env=isolated_environment,
        timeout=120,
    )
    assert recovery.status == 0
    assert recovery.stdout == (
        f"[OK] Resumed migration transaction: {transaction}\n"
    )
    assert recovery.stderr == ""
    final_journal = _read_strict_record(workspace.pki / "state/rollover/journal")
    assert final_journal["phase"] == "complete"
    assert final_journal["committed"] == "true"
    assert final_journal["recovery_action"] == "resume"
    assert final_journal["recovery_step"] == "resume-provenance-done"
    provenance = workspace.pki / "legacy" / transaction
    assert provenance.is_dir() and not provenance.is_symlink()
    assert (provenance / "README").is_file()
    assert (provenance / "quarantine/pki.env").read_text() == "legacy-config\n"
    assert not (workspace.pki / "pki.env").exists()
    generation_root_key = workspace.pki / "authorities/roots/g1/private/root-ca.key"
    generation_intermediate_key = (
        workspace.pki
        / "authorities/intermediates/g1-i1/private/intermediate-ca.key"
    )
    assert (
        generation_root_key.lstat().st_dev,
        generation_root_key.lstat().st_ino,
    ) == root_key_identity
    assert (
        generation_intermediate_key.lstat().st_dev,
        generation_intermediate_key.lstat().st_ino,
    ) == intermediate_key_identity
    assert (workspace.pki / "state/active-issuer").read_text() == (
        "root=g1\nintermediate=g1-i1\n"
    )
    transaction_directory = workspace.pki / "state/rollover" / transaction
    assert not transaction_directory.exists() and not transaction_directory.is_symlink()
    assert _metadata_tree(Path(isolated_environment["TMPDIR"])) == temporary_after_crash


@pytest.mark.parametrize(
    ("boundary", "phase"),
    MIGRATION_FAILURE_BOUNDARIES,
    ids=[boundary for boundary, _ in MIGRATION_FAILURE_BOUNDARIES],
)
def test_migration_sigkill_rollback_retry(
    rollover_tools: RolloverTools,
    legacy_rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
    boundary: str,
    phase: str,
) -> None:
    workspace = legacy_rollover_case_factory(f"migration-sigkill-retry-{boundary}")
    legacy_root_key = workspace.pki / "root-ca/private/root-ca.key"
    legacy_intermediate_key = (
        workspace.pki / "intermediate-ca/private/intermediate-ca.key"
    )
    root_key_identity = (
        legacy_root_key.lstat().st_dev,
        legacy_root_key.lstat().st_ino,
    )
    intermediate_key_identity = (
        legacy_intermediate_key.lstat().st_dev,
        legacy_intermediate_key.lstat().st_ino,
    )
    command, root_fingerprint, intermediate_fingerprint = _migration_inputs(
        rollover_tools,
        workspace,
        backup_receipt_factory,
        isolated_environment,
        process_runner,
    )
    journal = _crash_migration(
        command,
        workspace,
        boundary,
        isolated_environment,
        process_runner,
    )
    temporary_after_crash = _metadata_tree(Path(isolated_environment["TMPDIR"]))
    assert journal["phase"] == phase
    transaction = journal["transaction"]
    rollback = process_runner(
        _recovery_command(rollover_tools, workspace, transaction, "rollback"),
        env=isolated_environment,
        timeout=120,
    )
    assert rollback.status == 0
    assert rollback.stderr == ""
    assert (workspace.pki / "root-ca").is_dir()
    assert (workspace.pki / "intermediate-ca").is_dir()

    retry = process_runner(command, env=isolated_environment, timeout=120)
    assert retry.status == 0
    assert retry.stdout == (
        "[OK] Migrated legacy PKI state to root g1 and intermediate g1-i1\n"
    )
    assert retry.stderr == ""
    final_journal = _read_strict_record(workspace.pki / "state/rollover/journal")
    assert final_journal["transaction"] != transaction
    assert final_journal["phase"] == "complete"
    assert final_journal["committed"] == "true"
    for generation, kind, fingerprint in (
        ("g1", "root", root_fingerprint),
        ("g1-i1", "intermediate", intermediate_fingerprint),
    ):
        reservation = _read_strict_record(
            workspace.pki / "state/generation-reservations" / generation
        )
        assert reservation["kind"] == kind
        assert reservation["status"] == "consumed"
        assert reservation["fingerprint_sha256"] == fingerprint
    migrated_root_key = workspace.pki / "authorities/roots/g1/private/root-ca.key"
    migrated_intermediate_key = (
        workspace.pki
        / "authorities/intermediates/g1-i1/private/intermediate-ca.key"
    )
    assert (
        migrated_root_key.lstat().st_dev,
        migrated_root_key.lstat().st_ino,
    ) == root_key_identity
    assert (
        migrated_intermediate_key.lstat().st_dev,
        migrated_intermediate_key.lstat().st_ino,
    ) == intermediate_key_identity
    assert _metadata_tree(Path(isolated_environment["TMPDIR"])) == temporary_after_crash


@pytest.mark.parametrize(
    ("category", "boundary", "role", "diagnostic"),
    MIGRATION_HOSTILE_FILE_CASES,
    ids=[case[0] for case in MIGRATION_HOSTILE_FILE_CASES],
)
def test_migration_rejects_hostile_file_replacements(
    rollover_tools: RolloverTools,
    legacy_rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    private_text_writer: Callable[[Path, str], None],
    process_runner: Callable[..., ProcessResult],
    category: str,
    boundary: str,
    role: str,
    diagnostic: str,
) -> None:
    workspace = legacy_rollover_case_factory(f"migration-hostile-{category}")
    private_text_writer(workspace.pki / "pki.env", "legacy-config\n")
    command, _, _ = _migration_inputs(
        rollover_tools,
        workspace,
        backup_receipt_factory,
        isolated_environment,
        process_runner,
    )
    journal = _crash_migration(
        command,
        workspace,
        boundary,
        isolated_environment,
        process_runner,
    )
    temporary_after_crash = _metadata_tree(Path(isolated_environment["TMPDIR"]))
    transaction = journal["transaction"]
    hostile = _hostile_migration_path(workspace, journal, role)
    assert hostile.is_file() and not hostile.is_symlink()
    hostile.unlink()
    private_text_writer(hostile, f"hostile-{category}\n")
    before = _workspace_snapshot(workspace.root)

    recovery = process_runner(
        _recovery_command(rollover_tools, workspace, transaction, "rollback"),
        env=isolated_environment,
        timeout=120,
    )
    assert recovery.status == 1
    assert recovery.stdout == ""
    assert recovery.stderr == f"[ERROR] {diagnostic}\n"
    assert hostile.is_file() and not hostile.is_symlink()
    assert stat.S_IMODE(hostile.lstat().st_mode) == 0o600
    assert hostile.read_text() == f"hostile-{category}\n"
    assert _workspace_snapshot(workspace.root) == before
    assert _metadata_tree(Path(isolated_environment["TMPDIR"])) == temporary_after_crash


@pytest.mark.parametrize(
    ("authority", "boundary", "legacy_relative", "generation_relative"),
    MIGRATION_DUAL_DIRECTORY_CASES,
    ids=[case[0] for case in MIGRATION_DUAL_DIRECTORY_CASES],
)
def test_migration_rejects_simultaneous_dual_directories(
    rollover_tools: RolloverTools,
    legacy_rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    private_text_writer: Callable[[Path, str], None],
    process_runner: Callable[..., ProcessResult],
    authority: str,
    boundary: str,
    legacy_relative: str,
    generation_relative: str,
) -> None:
    workspace = legacy_rollover_case_factory(f"migration-dual-{authority}")
    private_text_writer(workspace.pki / "pki.env", "legacy-config\n")
    command, _, _ = _migration_inputs(
        rollover_tools,
        workspace,
        backup_receipt_factory,
        isolated_environment,
        process_runner,
    )
    journal = _crash_migration(
        command,
        workspace,
        boundary,
        isolated_environment,
        process_runner,
    )
    temporary_after_crash = _metadata_tree(Path(isolated_environment["TMPDIR"]))
    transaction = journal["transaction"]
    legacy = workspace.pki / legacy_relative
    generation = workspace.pki / generation_relative
    assert generation.is_dir() and not generation.is_symlink()
    legacy.mkdir(mode=0o700)
    before = _workspace_snapshot(workspace.root)

    recovery = process_runner(
        _recovery_command(rollover_tools, workspace, transaction, "rollback"),
        env=isolated_environment,
        timeout=120,
    )
    assert recovery.status == 1
    assert recovery.stdout == ""
    assert recovery.stderr == (
        f"[ERROR] {authority.title()} authority paths are simultaneously "
        "present or absent\n"
    )
    assert legacy.is_dir() and not legacy.is_symlink()
    assert generation.is_dir() and not generation.is_symlink()
    assert _workspace_snapshot(workspace.root) == before
    assert _metadata_tree(Path(isolated_environment["TMPDIR"])) == temporary_after_crash


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


def test_migration_prepares_missing_generation_destination_parents(
    rollover_tools: RolloverTools,
    legacy_rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> None:
    workspace = legacy_rollover_case_factory("migration-missing-destinations")
    (workspace.pki / "authorities/roots").rmdir()
    (workspace.pki / "authorities/intermediates").rmdir()
    (workspace.pki / "authorities").rmdir()
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

    assert result.status == 0, result
    assert result.stdout == (
        "[OK] Migrated legacy PKI state to root g1 and intermediate g1-i1\n"
    )
    assert result.stderr == ""
    for directory in (
        workspace.pki / "authorities",
        workspace.pki / "authorities/roots",
        workspace.pki / "authorities/intermediates",
    ):
        assert directory.is_dir() and not directory.is_symlink()
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert (workspace.pki / "state/active-issuer").read_text() == (
        "root=g1\nintermediate=g1-i1\n"
    )
    assert not tuple(Path(isolated_environment["TMPDIR"]).iterdir())


def test_missing_generation_destination_preparation_is_safely_retryable(
    rollover_tools: RolloverTools,
    legacy_rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> None:
    workspace = legacy_rollover_case_factory("migration-destination-retry")
    (workspace.pki / "authorities/roots").rmdir()
    (workspace.pki / "authorities/intermediates").rmdir()
    (workspace.pki / "authorities").rmdir()
    journal = workspace.pki / "state/rollover/journal"
    assert not journal.exists()
    receipt = backup_receipt_factory(workspace)
    receipt_content = receipt.read_text()
    receipt.write_text(
        receipt_content.replace(
            next(
                line
                for line in receipt_content.splitlines(keepends=True)
                if line.startswith("state_manifest_sha256=")
            ),
            f"state_manifest_sha256={'0' * 64}\n",
        )
    )
    receipt.chmod(0o600)
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

    failed = process_runner(command, env=isolated_environment, timeout=120)

    assert failed.status == 1
    assert failed.stdout == ""
    assert failed.stderr == (
        "[ERROR] Current public PKI state differs from the backed-up state manifest\n"
    )
    for directory in (
        workspace.pki / "authorities",
        workspace.pki / "authorities/roots",
        workspace.pki / "authorities/intermediates",
    ):
        assert directory.is_dir() and not directory.is_symlink()
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert not journal.exists()
    assert not (workspace.pki / "state/rollover/recovery-required").exists()
    status = process_runner(
        [
            *rollover_tools.rollover,
            "status",
            "--namespace",
            workspace.namespace,
        ],
        env=isolated_environment,
        timeout=30,
    )
    assert status.status == 1
    assert status.stdout == (
        "status=legacy\n"
        "recovery_required=false\n"
        "action=run platform-pki backup, then platform-pki ca-rollover migrate\n"
    )
    assert status.stderr == ""

    receipt.write_text(receipt_content)
    receipt.chmod(0o600)
    retry = process_runner(command, env=isolated_environment, timeout=120)

    assert retry.status == 0, retry
    assert retry.stdout == (
        "[OK] Migrated legacy PKI state to root g1 and intermediate g1-i1\n"
    )
    assert retry.stderr == ""
    assert (workspace.pki / "state/active-issuer").read_text() == (
        "root=g1\nintermediate=g1-i1\n"
    )
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
