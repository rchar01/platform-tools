from __future__ import annotations

import os
import signal
import sys
from collections.abc import Callable, Mapping
from pathlib import Path

import pytest

from src.platform_pki.ca_rollover_migrate import (
    MIGRATION_FAULT_CHECKPOINTS,
    MIGRATION_MUTATION_CHECKPOINTS,
)

from ..harness import ProcessResult
from .conftest import RolloverTools, RolloverWorkspace
from .migration_harness import (
    managed_openssl_dir_normalizer,
    run_differential_case,
    snapshot_state,
)
from .test_ca_rollover_migrate import (
    MIGRATION_PHASES,
    _certificate_fingerprint,
    _read_strict_record,
)
from .test_ca_rollover_python_recover import (
    _LEGACY_NORMALIZATION,
    _create_backup,
    _normalize_recovery_output,
    _recovery_content_normalizer,
    _replace_dynamic_tokens,
)


pytestmark = pytest.mark.pki

REPOSITORY = Path(__file__).resolve().parents[2]
ORACLE = (
    REPOSITORY
    / "tests/pki/oracles/platform-pki-ca-rollover/platform-pki-ca-rollover"
)
DRIVER = REPOSITORY / "tests/pki/ca_rollover_migrate_driver.py"
UNIFIED_PLATFORM_PKI = REPOSITORY / "bin/platform-pki"
MUTATION_PHASES = {
    "root-move-before-journal": "reserved",
    "intermediate-move-before-journal": "root-renamed",
    "active-publication-before-journal": "active-pending",
}
_IMMUTABLE_EVIDENCE = frozenset(
    {
        "baseline",
        "services",
        "issuer-identities",
        "quarantine-identities",
        "root-openssl.cnf",
        "intermediate-openssl.cnf",
        "root-openssl.rollback",
        "intermediate-openssl.rollback",
    }
)


def _workspace(root: Path) -> RolloverWorkspace:
    return RolloverWorkspace(
        root=root,
        namespace=root / "ns",
        pki=root / "ns/pki",
        private_repo=root / "private",
        passphrase_file=root / "passphrase",
    )


def _receipt(root: Path) -> Path:
    receipts = tuple((root / "differential-backups").glob("*.receipt"))
    assert len(receipts) == 1
    return receipts[0]


def _arguments(
    root: Path,
    root_fingerprint: str,
    intermediate_fingerprint: str,
) -> tuple[str | Path, ...]:
    workspace = _workspace(root)
    return (
        "--namespace",
        workspace.namespace,
        "--private-repo",
        workspace.private_repo,
        "--backup-receipt",
        _receipt(root),
        "--yes",
        "--expected-root-sha256",
        root_fingerprint,
        "--expected-intermediate-sha256",
        intermediate_fingerprint,
    )


def _python_command(
    workspace: RolloverWorkspace,
    receipt: Path,
    root_fingerprint: str,
    intermediate_fingerprint: str,
) -> tuple[str | Path, ...]:
    return (
        sys.executable,
        DRIVER,
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
    )


def _prepared_command(
    workspace: RolloverWorkspace,
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> tuple[str | Path, ...]:
    (workspace.pki / "state/rollover/journal").unlink(missing_ok=True)
    receipt = backup_receipt_factory(workspace)
    return _python_command(
        workspace,
        receipt,
        _certificate_fingerprint(
            workspace.pki / "root-ca/certs/root-ca.crt",
            environment,
            process_runner,
        ),
        _certificate_fingerprint(
            workspace.pki / "intermediate-ca/certs/intermediate-ca.crt",
            environment,
            process_runner,
        ),
    )


def _normalized_evidence(
    workspace: RolloverWorkspace, transaction: str, *, retained: bool
) -> dict[str, tuple[object, ...]]:
    def token_normalizer(value: str) -> str:
        return _replace_dynamic_tokens(value, _LEGACY_NORMALIZATION)

    entries = snapshot_state(
        workspace.pki,
        (
            managed_openssl_dir_normalizer(workspace.root),
            _recovery_content_normalizer(_LEGACY_NORMALIZATION, workspace.root),
        ),
        (token_normalizer,),
    )
    normalized_transaction = token_normalizer(transaction)
    prefix = (
        f"legacy/{normalized_transaction}/"
        if retained
        else f"state/rollover/{normalized_transaction}/"
    )
    result = {}
    for entry in entries:
        if not entry.path.startswith(prefix):
            continue
        relative = entry.path.removeprefix(prefix)
        if relative not in _IMMUTABLE_EVIDENCE:
            continue
        result[relative] = (
            entry.kind,
            entry.mode,
            entry.owner,
            entry.group,
            entry.links,
            entry.size,
            entry.content_sha256,
            entry.link_target,
        )
    assert result.keys() == _IMMUTABLE_EVIDENCE
    return result


def test_python_migration_success_matches_frozen_bash(
    tmp_path: Path,
    rollover_tools: RolloverTools,
    legacy_rollover_case_factory: Callable[[str], RolloverWorkspace],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> None:
    seed = legacy_rollover_case_factory("python-migration-differential-seed")
    root_fingerprint = _certificate_fingerprint(
        seed.pki / "root-ca/certs/root-ca.crt",
        isolated_environment,
        process_runner,
    )
    intermediate_fingerprint = _certificate_fingerprint(
        seed.pki / "intermediate-ca/certs/intermediate-ca.crt",
        isolated_environment,
        process_runner,
    )

    def prepare(root: Path, environment: Mapping[str, str]) -> None:
        workspace = _workspace(root)
        (workspace.pki / "state/rollover/journal").unlink(missing_ok=True)
        backup_environment = dict(environment)
        backup_environment["PLATFORM_TOOLS_LIB_DIR"] = os.fspath(
            REPOSITORY / "tests/pki/oracles/final-bash-source/lib"
        )
        _create_backup(
            rollover_tools, workspace, backup_environment, process_runner
        )

    case_root = tmp_path / "python-migration-differential"
    environment = dict(isolated_environment)
    environment["PLATFORM_TOOLS_LIB_DIR"] = os.fspath(ORACLE.parent / "lib")
    result = run_differential_case(
        seed.root,
        case_root,
        Path("ns/pki"),
        lambda root: (
            ORACLE,
            "migrate",
            *_arguments(root, root_fingerprint, intermediate_fingerprint),
        ),
        lambda root: (
            sys.executable,
            DRIVER,
            *_arguments(root, root_fingerprint, intermediate_fingerprint),
        ),
        environment,
        output_normalizers=(
            lambda root, value: _normalize_recovery_output(
                root, value, _LEGACY_NORMALIZATION
            ),
        ),
        content_normalizers=(
            _recovery_content_normalizer(
                _LEGACY_NORMALIZATION,
                seed.root,
                case_root / "bash",
                case_root / "python",
            ),
        ),
        path_normalizers=(
            lambda value: _replace_dynamic_tokens(value, _LEGACY_NORMALIZATION),
        ),
        runner=process_runner,
        run_options={"timeout": 120},
        bash_prepare=prepare,
        python_prepare=prepare,
    )

    result.assert_equivalent()


@pytest.mark.parametrize(
    "checkpoint", MIGRATION_FAULT_CHECKPOINTS, ids=MIGRATION_FAULT_CHECKPOINTS
)
def test_python_migration_intermediate_state_matches_frozen_bash(
    checkpoint: str,
    tmp_path: Path,
    rollover_tools: RolloverTools,
    legacy_rollover_case_factory: Callable[[str], RolloverWorkspace],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> None:
    seed = legacy_rollover_case_factory(
        f"python-migration-intermediate-{checkpoint}-seed"
    )
    root_fingerprint = _certificate_fingerprint(
        seed.pki / "root-ca/certs/root-ca.crt",
        isolated_environment,
        process_runner,
    )
    intermediate_fingerprint = _certificate_fingerprint(
        seed.pki / "intermediate-ca/certs/intermediate-ca.crt",
        isolated_environment,
        process_runner,
    )

    def prepare(root: Path, environment: Mapping[str, str]) -> None:
        workspace = _workspace(root)
        (workspace.pki / "state/rollover/journal").unlink(missing_ok=True)
        if checkpoint == "after-active":
            quarantine = workspace.pki / "pki.env"
            quarantine.write_bytes(b"legacy-scaffolding=true\n")
            quarantine.chmod(0o600)
        _create_backup(
            rollover_tools,
            workspace,
            dict(
                environment,
                PLATFORM_TOOLS_LIB_DIR=os.fspath(
                    REPOSITORY / "tests/pki/oracles/final-bash-source/lib"
                ),
            ),
            process_runner,
        )

    case_root = tmp_path / f"python-migration-intermediate-{checkpoint}"
    result = run_differential_case(
        seed.root,
        case_root,
        Path("ns/pki"),
        lambda root: (
            ORACLE,
            "migrate",
            *_arguments(root, root_fingerprint, intermediate_fingerprint),
        ),
        lambda root: (
            sys.executable,
            DRIVER,
            *_arguments(root, root_fingerprint, intermediate_fingerprint),
        ),
        dict(
            isolated_environment,
            PLATFORM_TOOLS_LIB_DIR=os.fspath(ORACLE.parent / "lib"),
            PLATFORM_PKI_MIGRATE_CRASH_AT=checkpoint,
        ),
        output_normalizers=(
            lambda root, value: _normalize_recovery_output(
                root, value, _LEGACY_NORMALIZATION
            ),
        ),
        content_normalizers=(
            _recovery_content_normalizer(
                _LEGACY_NORMALIZATION,
                seed.root,
                case_root / "bash",
                case_root / "python",
            ),
        ),
        path_normalizers=(
            lambda value: _replace_dynamic_tokens(value, _LEGACY_NORMALIZATION),
        ),
        runner=process_runner,
        run_options={"timeout": 120},
        bash_prepare=prepare,
        python_prepare=prepare,
    )

    result.assert_equivalent()
    assert result.python.process.status == 137
    for implementation in ("bash", "python"):
        pki = case_root / implementation / "ns/pki"
        journal = _read_strict_record(pki / "state/rollover/journal")
        assert journal["phase"] == MIGRATION_PHASES[checkpoint]
        assert journal["committed"] == "false"
        assert (pki / "root-ca").exists() == (
            checkpoint in ("after-journal", "after-reservations")
        )
        assert (pki / "authorities/roots/g1").exists() == (
            checkpoint not in ("after-journal", "after-reservations")
        )
        assert (pki / "state/active-issuer").exists() == (
            checkpoint == "after-active"
        )


@pytest.mark.parametrize(
    "checkpoint", MIGRATION_FAULT_CHECKPOINTS, ids=MIGRATION_FAULT_CHECKPOINTS
)
@pytest.mark.parametrize("action", ("rollback", "resume"))
def test_python_migration_crash_journal_is_recoverable(
    action: str,
    checkpoint: str,
    rollover_tools: RolloverTools,
    legacy_rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> None:
    workspace = legacy_rollover_case_factory(f"python-migration-crash-{checkpoint}")
    (workspace.pki / "state/rollover/journal").unlink(missing_ok=True)
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
    crashed = process_runner(
        _python_command(
            workspace,
            receipt,
            root_fingerprint,
            intermediate_fingerprint,
        ),
        env=dict(
            isolated_environment,
            PLATFORM_PKI_MIGRATE_CRASH_AT=checkpoint,
        ),
        timeout=120,
    )

    assert crashed.status == 137
    assert crashed.stdout == ""
    assert crashed.stderr == ""
    journal = _read_strict_record(workspace.pki / "state/rollover/journal")
    assert journal["operation"] == "legacy-migrate"
    assert journal["phase"] == MIGRATION_PHASES[checkpoint]
    assert journal["committed"] == "false"

    recovered = process_runner(
        (
            UNIFIED_PLATFORM_PKI,
            "ca-rollover",
            "recover",
            "--namespace",
            workspace.namespace,
            "--transaction",
            journal["transaction"],
            "--action",
            action,
            "--yes",
        ),
        env=isolated_environment,
        timeout=120,
    )
    assert recovered.status == 0, recovered
    terminal = _read_strict_record(workspace.pki / "state/rollover/journal")
    assert terminal["phase"] == ("rolled-back" if action == "rollback" else "complete")
    assert terminal["committed"] == "true"


@pytest.mark.parametrize(
    "content",
    (
        "operation=legacy-migrate\ncommitted=true\n",
        "schema=99\noperation=legacy-migrate\ncommitted=true\n",
        "schema=2\noperation=unsupported\ncommitted=true\n",
    ),
    ids=("malformed", "unsupported-schema", "unsupported-operation"),
)
def test_python_migration_never_overwrites_invalid_committed_journal(
    content: str,
    legacy_rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> None:
    workspace = legacy_rollover_case_factory("python-invalid-terminal-journal")
    command = _prepared_command(
        workspace,
        backup_receipt_factory,
        isolated_environment,
        process_runner,
    )
    journal = workspace.pki / "state/rollover/journal"
    journal.write_text(content, encoding="ascii")
    journal.chmod(0o600)
    before = journal.read_bytes(), journal.stat()

    result = process_runner(
        command,
        env=isolated_environment,
        timeout=120,
    )

    after = journal.stat()
    assert result.status == 1
    assert result.stdout == ""
    assert result.stderr == (
        "[ERROR] PKI recovery is required before this command can continue: "
        f"{journal}\n"
    )
    assert journal.read_bytes() == before[0]
    assert (after.st_dev, after.st_ino, after.st_mtime_ns) == (
        before[1].st_dev,
        before[1].st_ino,
        before[1].st_mtime_ns,
    )


@pytest.mark.parametrize(
    ("race", "diagnostic"),
    (
        ("journal-after-gate", "Existing PKI recovery journal identity changed"),
        ("root-reservation-original", "Migration publication destination changed"),
        ("intermediate-reservation-original", "Migration publication destination changed"),
        ("root-reservation-stage", "Migration staged-file publication failed"),
        ("intermediate-reservation-stage", "Migration staged-file publication failed"),
        ("root-reservation-reserved", "Migration publication destination changed"),
        ("intermediate-reservation-reserved", "Migration publication destination changed"),
    ),
)
def test_python_migration_rejects_replaced_journal_and_reservations(
    race: str,
    diagnostic: str,
    legacy_rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> None:
    workspace = legacy_rollover_case_factory(f"python-race-{race}")
    if race == "journal-after-gate":
        command = _prepared_command(
            workspace,
            backup_receipt_factory,
            isolated_environment,
            process_runner,
        )
        interrupted = process_runner(
            command,
            env=dict(
                isolated_environment,
                PLATFORM_PKI_MIGRATE_FAIL_AT="after-journal",
            ),
            timeout=120,
        )
        assert interrupted.status == 1
        pending = _read_strict_record(workspace.pki / "state/rollover/journal")
        recovered = process_runner(
            (
                UNIFIED_PLATFORM_PKI,
                "ca-rollover",
                "recover",
                "--namespace",
                workspace.namespace,
                "--transaction",
                pending["transaction"],
                "--action",
                "rollback",
                "--yes",
            ),
            env=isolated_environment,
            timeout=120,
        )
        assert recovered.status == 0, recovered
    else:
        command = _prepared_command(
            workspace,
            backup_receipt_factory,
            isolated_environment,
            process_runner,
        )

    result = process_runner(
        command,
        env=dict(
            isolated_environment,
            PLATFORM_PKI_MIGRATE_DRIVER_RACE=race,
        ),
        timeout=120,
    )

    assert result.status == 1
    assert result.stdout == ""
    assert result.stderr.startswith(f"[ERROR] {diagnostic}")
    journal = workspace.pki / "state/rollover/journal"
    if race == "journal-after-gate":
        assert journal.read_bytes() == b"hostile-journal\n"
    else:
        record = _read_strict_record(journal)
        assert record["phase"] == (
            "quarantined" if race.endswith("-reserved") else "pre-mutation"
        )
        assert record["committed"] == "false"
        assert (workspace.pki / "state/rollover/recovery-required").is_file()


@pytest.mark.parametrize(
    ("race", "phase"),
    (
        ("nested-root-ca", "reserved"),
        ("nested-intermediate-ca", "root-renamed"),
        ("nested-before-active", "active-pending"),
    ),
)
def test_python_migration_fails_closed_on_nested_authority_changes(
    race: str,
    phase: str,
    legacy_rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> None:
    workspace = legacy_rollover_case_factory(f"python-nested-race-{race}")
    result = process_runner(
        _prepared_command(
            workspace,
            backup_receipt_factory,
            isolated_environment,
            process_runner,
        ),
        env=dict(
            isolated_environment,
            PLATFORM_PKI_MIGRATE_DRIVER_RACE=race,
        ),
        timeout=120,
    )

    assert result.status == 1
    assert result.stdout == ""
    assert "authority tree changed" in result.stderr
    journal = _read_strict_record(workspace.pki / "state/rollover/journal")
    assert journal["phase"] == phase
    assert journal["committed"] == "false"
    assert (workspace.pki / "state/rollover/recovery-required").is_file()


@pytest.mark.parametrize(
    ("race", "phase", "diagnostic"),
    (
        ("config-authority", "intermediate-renamed", "root authority tree changed"),
        ("issuer-public", "configs-published", "public PKI state differs"),
        ("quarantine-private", "issuers-published", "root authority tree changed"),
        ("active-inventory", "active-pending", "Service inventory identity changed"),
        (
            "active-receipt",
            "active-pending",
            "Migration backup receipt identity changed",
        ),
    ),
)
def test_python_migration_rechecks_frozen_reviewed_sources_before_groups(
    race: str,
    phase: str,
    diagnostic: str,
    legacy_rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> None:
    workspace = legacy_rollover_case_factory(f"python-reviewed-race-{race}")
    if race == "quarantine-private":
        quarantine_source = workspace.pki / "pki.env"
        quarantine_source.write_bytes(b"legacy-scaffolding=true\n")
        quarantine_source.chmod(0o600)
    result = process_runner(
        _prepared_command(
            workspace,
            backup_receipt_factory,
            isolated_environment,
            process_runner,
        ),
        env=dict(
            isolated_environment,
            PLATFORM_PKI_MIGRATE_DRIVER_RACE=race,
        ),
        timeout=120,
    )

    assert result.status == 1
    assert result.stdout == ""
    assert diagnostic in result.stderr
    journal = _read_strict_record(workspace.pki / "state/rollover/journal")
    assert journal["phase"] == phase
    assert journal["committed"] == "false"
    assert (workspace.pki / "state/rollover/recovery-required").is_file()


@pytest.mark.parametrize(
    "checkpoint", MIGRATION_MUTATION_CHECKPOINTS, ids=MIGRATION_MUTATION_CHECKPOINTS
)
@pytest.mark.parametrize(
    ("mode", "status"),
    (("CRASH", 137), ("FAIL", 1)),
)
def test_python_migration_mutation_boundary_journal_and_tree(
    checkpoint: str,
    mode: str,
    status: int,
    legacy_rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> None:
    workspace = legacy_rollover_case_factory(
        f"python-mutation-{mode.lower()}-{checkpoint}"
    )
    result = process_runner(
        _prepared_command(
            workspace,
            backup_receipt_factory,
            isolated_environment,
            process_runner,
        ),
        env=dict(
            isolated_environment,
            **{f"PLATFORM_PKI_MIGRATE_{mode}_AT": checkpoint},
        ),
        timeout=120,
    )

    assert result.status == status
    assert result.stdout == ""
    journal = _read_strict_record(workspace.pki / "state/rollover/journal")
    assert journal["phase"] == MUTATION_PHASES[checkpoint]
    assert journal["committed"] == "false"
    root_legacy = workspace.pki / "root-ca"
    root_generation = workspace.pki / "authorities/roots/g1"
    intermediate_legacy = workspace.pki / "intermediate-ca"
    intermediate_generation = workspace.pki / "authorities/intermediates/g1-i1"
    assert root_generation.is_dir() and not root_legacy.exists()
    assert (intermediate_generation.is_dir(), intermediate_legacy.is_dir()) == (
        checkpoint != "root-move-before-journal",
        checkpoint == "root-move-before-journal",
    )
    assert (workspace.pki / "state/active-issuer").exists() == (
        checkpoint == "active-publication-before-journal"
    )
    marker = workspace.pki / "state/rollover/recovery-required"
    assert marker.exists() == (mode != "CRASH")
    evidence = _normalized_evidence(
        workspace, journal["transaction"], retained=False
    )
    recovered = process_runner(
        (
            UNIFIED_PLATFORM_PKI,
            "ca-rollover",
            "recover",
            "--namespace",
            workspace.namespace,
            "--transaction",
            journal["transaction"],
            "--action",
            "resume",
            "--yes",
        ),
        env=isolated_environment,
        timeout=120,
    )
    assert recovered.status == 0, recovered
    terminal = _read_strict_record(workspace.pki / "state/rollover/journal")
    assert terminal["phase"] == "complete"
    assert terminal["committed"] == "true"
    assert _normalized_evidence(
        workspace, journal["transaction"], retained=True
    ) == evidence
    assert (workspace.pki / "state/active-issuer").read_bytes() == (
        b"root=g1\nintermediate=g1-i1\n"
    )


@pytest.mark.parametrize(
    ("process_signal", "checkpoint"),
    (
        (signal.SIGHUP, "root-move-before-journal"),
        (signal.SIGINT, "intermediate-move-before-journal"),
        (signal.SIGTERM, "active-publication-before-journal"),
    ),
    ids=("SIGHUP-root", "SIGINT-intermediate", "SIGTERM-active"),
)
def test_python_migration_signals_cover_post_mutation_pre_journal_windows(
    process_signal: signal.Signals,
    checkpoint: str,
    legacy_rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> None:
    workspace = legacy_rollover_case_factory(
        f"python-signal-{process_signal.name}-{checkpoint}"
    )
    result = process_runner(
        _prepared_command(
            workspace,
            backup_receipt_factory,
            isolated_environment,
            process_runner,
        ),
        env=dict(
            isolated_environment,
            PLATFORM_PKI_MIGRATE_SIGNAL_AT=checkpoint,
            PLATFORM_PKI_MIGRATE_SIGNAL=str(process_signal.value),
        ),
        timeout=120,
    )

    assert result.status == 128 + process_signal
    assert result.stdout == ""
    journal = _read_strict_record(workspace.pki / "state/rollover/journal")
    assert journal["phase"] == MUTATION_PHASES[checkpoint]
    assert journal["committed"] == "false"
    assert (workspace.pki / "state/rollover/recovery-required").is_file()
    evidence = _normalized_evidence(
        workspace, journal["transaction"], retained=False
    )
    recovered = process_runner(
        (
            UNIFIED_PLATFORM_PKI,
            "ca-rollover",
            "recover",
            "--namespace",
            workspace.namespace,
            "--transaction",
            journal["transaction"],
            "--action",
            "resume",
            "--yes",
        ),
        env=isolated_environment,
        timeout=120,
    )
    assert recovered.status == 0, recovered
    terminal = _read_strict_record(workspace.pki / "state/rollover/journal")
    assert terminal["phase"] == "complete"
    assert terminal["committed"] == "true"
    assert _normalized_evidence(
        workspace, journal["transaction"], retained=True
    ) == evidence
