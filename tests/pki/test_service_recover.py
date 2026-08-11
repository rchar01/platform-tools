from __future__ import annotations

import fcntl
import os
import shutil
import signal
import sys
import time
from collections.abc import Callable, Mapping
from pathlib import Path

import pytest

from src.platform_pki.service_transaction import (
    MANAGED_RENEW_ARCHIVE_MEMBER_ORDER,
    SERVICE_CONTAINER_ORDER,
    ServiceKeyAction,
    ServiceOperation,
    managed_rollback_order,
    parse_service_retained_rollback,
    parse_service_retained_terminal,
    parse_service_transaction,
    serialize_service_retained_terminal,
)
from src.platform_pki.persisted_identity import parse_file_identity
from src.platform_pki.filesystem import FileIdentity, identity_at
from src.platform_pki.service_recover import SERVICE_RECOVERY_CHECKPOINTS

from ..harness import ManagedProcess, ProcessResult
from .service_recover_case import (
    ServiceRecoveryCase,
    build_service_recovery_case,
)
from .support import assert_result, environment


pytestmark = pytest.mark.pki

REPOSITORY = Path(__file__).resolve().parents[2]
DRIVER = REPOSITORY / "tests/pki/service_recover_driver.py"

CHECKPOINT_SCENARIOS = {
    "issue-precommit-created-containers": (
        "Issue rollback reaches created service-container and common-file points."
    ),
    "renew-precommit-existing-archive-root": (
        "Renewal rollback reaches archive-member and archive-root restoration points."
    ),
    "renew-precommit-created-archive-root": (
        "Renewal rollback reaches created archive-root removal points."
    ),
    "renew-publication-window": (
        "Renewal reconciliation reaches publication-window journal points."
    ),
    "issue-directory-stage-window": (
        "Issue recovery discards an exact unpublished private directory stage."
    ),
    "renew-postcommit": (
        "Committed renewal reaches cleanup-start and archive-marker cleanup points."
    ),
}
# Every declared point is applicable to at least one scenario above. Keep an
# explicit map if a future operation-specific point cannot be reached here.
CHECKPOINT_EXCLUSIONS: dict[str, str] = {}


def _run(
    process_runner: Callable[..., ProcessResult],
    case: ServiceRecoveryCase,
    *,
    env: Mapping[str, str] | None = None,
    transaction: str | None = None,
) -> ProcessResult:
    return process_runner(
        [
            sys.executable,
            DRIVER,
            "--pki-dir",
            case.pki,
            "--transaction",
            case.transaction if transaction is None else transaction,
        ],
        env=os.environ if env is None else env,
        timeout=120,
    )


def _start_paused(
    process_starter: Callable[..., ManagedProcess],
    case: ServiceRecoveryCase,
    tmp_path: Path,
    point: str,
) -> tuple[ManagedProcess, Path]:
    marker = tmp_path / "recovery-paused"
    release = tmp_path / "recovery-release"
    process = process_starter(
        [
            sys.executable,
            DRIVER,
            "--pki-dir",
            case.pki,
            "--transaction",
            case.transaction,
        ],
        env=environment(
            os.environ,
            PLATFORM_PKI_SERVICE_RECOVER_PAUSE_AT=point,
            PLATFORM_PKI_SERVICE_RECOVER_PAUSE_MARKER=os.fspath(marker),
            PLATFORM_PKI_SERVICE_RECOVER_PAUSE_RELEASE=os.fspath(release),
        ),
        timeout=120,
    )
    deadline = time.monotonic() + 10
    while (
        not marker.exists()
        and process.observe().status is None
        and time.monotonic() < deadline
    ):
        time.sleep(0.02)
    assert marker.exists(), process.observe()
    return process, release


def _live_file(path: Path) -> FileIdentity:
    identity = identity_at(path)
    assert isinstance(identity, FileIdentity)
    return identity


def _replace_file(path: Path) -> FileIdentity:
    replacement = path.with_name(f".{path.name}.race-replacement")
    replacement.write_bytes(path.read_bytes())
    replacement.chmod(path.stat().st_mode & 0o777)
    os.replace(replacement, path)
    return _live_file(path)


def _record(case: ServiceRecoveryCase):
    return parse_service_transaction(
        (case.pki / "state/service/recovery-journal").read_bytes(),
        pki_dir=case.pki,
    )


def _assert_private_control_final(case: ServiceRecoveryCase, outcome: str) -> None:
    transaction = case.pki / f"state/service/transactions/{case.transaction}"
    assert not (case.pki / "state/service/recovery-journal").exists()
    assert not (transaction / "stage").exists()
    assert not (transaction / "backup").exists()
    terminal = parse_service_retained_terminal((transaction / "terminal").read_bytes())
    assert terminal["transaction"] == case.transaction
    assert terminal["outcome"] == outcome


def _assert_original_destinations(case: ServiceRecoveryCase) -> None:
    for key, original in case.original_destinations.items():
        destination = Path(case.values[f"{key}_destination"])
        if original is None:
            assert not destination.exists(), key
        elif original == b"":
            assert destination.is_dir(), key
        else:
            assert destination.read_bytes() == original, key


def _full_renewal_case(
    root: Path,
    *,
    staged_count: int | None = None,
    backed_up_count: int | None = None,
    published: int | None = None,
    publication_pending: bool = False,
    committed: bool = False,
) -> ServiceRecoveryCase:
    return build_service_recovery_case(
        root,
        operation=ServiceOperation.RENEW,
        key_action=ServiceKeyAction.ROTATE,
        archive_members=MANAGED_RENEW_ARCHIVE_MEMBER_ORDER,
        existing_archive_root=True,
        staged_count=staged_count,
        backed_up_count=backed_up_count,
        published=published,
        publication_pending=publication_pending,
        committed=committed,
    )


@pytest.mark.parametrize(
    ("operation", "key_action", "archive_members", "existing_archive_root", "directories"),
    (
        (ServiceOperation.ISSUE, ServiceKeyAction.CREATE, None, False, ()),
        (ServiceOperation.ISSUE, ServiceKeyAction.ROTATE, None, False, SERVICE_CONTAINER_ORDER),
        (
            ServiceOperation.RENEW,
            ServiceKeyAction.REUSE,
            (".platform-pki-renew-archive", "tls.crt", "issuer"),
            True,
            SERVICE_CONTAINER_ORDER,
        ),
        (
            ServiceOperation.RENEW,
            ServiceKeyAction.ROTATE,
            MANAGED_RENEW_ARCHIVE_MEMBER_ORDER,
            False,
            SERVICE_CONTAINER_ORDER,
        ),
        (
            ServiceOperation.RENEW,
            ServiceKeyAction.ROTATE,
            MANAGED_RENEW_ARCHIVE_MEMBER_ORDER,
            True,
            SERVICE_CONTAINER_ORDER,
        ),
    ),
)
def test_precommit_recovery_restores_every_published_prefix(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    operation: ServiceOperation,
    key_action: ServiceKeyAction,
    archive_members: tuple[str, ...] | None,
    existing_archive_root: bool,
    directories: tuple[str, ...],
) -> None:
    case = build_service_recovery_case(
        tmp_path,
        operation=operation,
        key_action=key_action,
        archive_members=archive_members,
        existing_archive_root=existing_archive_root,
        existing_service_directories=directories,
        published=-1,
    )
    archive_root = Path(case.values["archive_root_destination"])
    archive_snapshot = (
        parse_file_identity(case.values["archive_root_snapshot_identity"])
        if existing_archive_root
        else None
    )
    assert archive_snapshot is None or isinstance(archive_snapshot, FileIdentity)
    archive_mtime = None if archive_snapshot is None else archive_snapshot.mtime_ns

    result = _run(process_runner, case)

    assert_result(
        result,
        0,
        stdout="[OK] Recovered managed service transaction: app (failed-pre-commit)\n",
        stderr="",
    )
    _assert_original_destinations(case)
    if archive_mtime is not None:
        assert archive_root.stat().st_mtime_ns == archive_mtime
    transaction = case.pki / f"state/service/transactions/{case.transaction}"
    rollback = parse_service_retained_rollback(
        (transaction / "rollback-complete").read_bytes()
    )
    assert rollback["completed_count"] == rollback["published_count"]
    _assert_private_control_final(case, "failed-pre-commit")


@pytest.mark.parametrize("operation", (ServiceOperation.ISSUE, ServiceOperation.RENEW))
def test_committed_recovery_only_cleans_private_evidence(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    operation: ServiceOperation,
) -> None:
    case = build_service_recovery_case(
        tmp_path,
        operation=operation,
        key_action=ServiceKeyAction.REUSE,
        existing_archive_root=operation is ServiceOperation.RENEW,
        committed=True,
    )
    record = _record(case)
    destinations = {
        mutation.key: (
            Path(mutation.destination).read_bytes()
            if Path(mutation.destination).is_file()
            else None
        )
        for mutation in record.mutations
        if mutation.key != "archive_marker"
    }

    result = _run(process_runner, case)

    assert_result(
        result,
        0,
        stdout="[OK] Recovered managed service transaction: app (succeeded)\n",
        stderr="",
    )
    for mutation in record.mutations:
        destination = Path(mutation.destination)
        if mutation.key == "archive_marker":
            assert not destination.exists()
        elif destinations[mutation.key] is None:
            assert destination.is_dir()
        else:
            assert destination.read_bytes() == destinations[mutation.key]
    _assert_private_control_final(case, "succeeded")

    repeated = _run(process_runner, case)
    assert_result(
        repeated,
        0,
        stdout="[OK] Managed service transaction already recovered: app (succeeded)\n",
        stderr="",
    )


@pytest.mark.parametrize(
    ("prefix", "count"),
    (
        *(("staging", count) for count in range(28)),
        *(("backup", count) for count in range(10)),
    ),
)
def test_recovery_accepts_every_incomplete_private_prefix(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    prefix: str,
    count: int,
) -> None:
    case = (
        _full_renewal_case(tmp_path, staged_count=count)
        if prefix == "staging"
        else _full_renewal_case(tmp_path, backed_up_count=count)
    )

    result = _run(process_runner, case)

    assert_result(result, 0, stderr="")
    _assert_original_destinations(case)
    _assert_private_control_final(case, "failed-pre-commit")


@pytest.mark.parametrize("published", range(23))
def test_recovery_reconciles_every_publication_mutation_window(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    published: int,
) -> None:
    case = _full_renewal_case(
        tmp_path,
        published=published,
        publication_pending=True,
    )

    result = _run(process_runner, case)

    assert_result(result, 0, stderr="")
    _assert_original_destinations(case)
    _assert_private_control_final(case, "failed-pre-commit")


def test_recovery_discards_exact_unpublished_directory_stage(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
) -> None:
    case = build_service_recovery_case(
        tmp_path,
        existing_service_directories=(),
        published=0,
        publication_pending=True,
        directory_stage_pending=True,
    )
    stage = Path(case.values["stage_dir"]) / "service_root"

    result = _run(process_runner, case)

    assert_result(result, 0, stderr="")
    assert not stage.exists()
    _assert_original_destinations(case)
    _assert_private_control_final(case, "failed-pre-commit")


@pytest.mark.parametrize("kind", ("directory", "file"))
@pytest.mark.parametrize(
    "point",
    (
        "publication-reconcile-before-evidence",
        "publication-reconcile-before-journal-rewrite",
    ),
)
def test_publication_reconciliation_rejects_replacement_after_preflight(
    tmp_path: Path,
    process_starter: Callable[..., ManagedProcess],
    process_runner: Callable[..., ProcessResult],
    kind: str,
    point: str,
) -> None:
    case = build_service_recovery_case(
        tmp_path,
        existing_service_directories=() if kind == "directory" else SERVICE_CONTAINER_ORDER,
        published=0,
        publication_pending=True,
    )
    record = _record(case)
    key = record.publication_order[0]
    destination = Path(case.values[f"{key}_destination"])
    next_destination = Path(case.values[f"{record.publication_order[1]}_destination"])
    next_before = identity_at(next_destination)
    process, release = _start_paused(
        process_starter,
        case,
        tmp_path,
        point,
    )
    displaced = tmp_path / f"authenticated-{key}"
    if kind == "directory":
        os.replace(destination, displaced)
        destination.mkdir(mode=0o700)
    else:
        replacement = tmp_path / f"replacement-{key}"
        shutil.copy2(destination, replacement)
        os.replace(destination, displaced)
        os.replace(replacement, destination)
    replacement = _live_file(destination)
    release.write_bytes(b"release\n")

    result = process.wait()

    assert result.status == 1, result
    assert _live_file(destination) == replacement
    assert displaced.exists()
    assert identity_at(next_destination) == next_before
    assert _record(case)["published_count"] == "0"
    assert (case.pki / "state/service/recovery-journal").is_file()

    repeated = _run(process_runner, case)
    assert repeated.status == 1, repeated
    assert _live_file(destination) == replacement
    assert displaced.exists()
    assert identity_at(next_destination) == next_before
    assert (case.pki / "state/service/recovery-journal").is_file()


@pytest.mark.parametrize("kind", ("directory", "file"))
@pytest.mark.parametrize(
    "point",
    (
        "publication-reconcile-before-evidence",
        "publication-reconcile-before-journal-rewrite",
    ),
)
def test_publication_reconciliation_restarts_from_authenticated_identity(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    kind: str,
    point: str,
) -> None:
    case = build_service_recovery_case(
        tmp_path,
        existing_service_directories=() if kind == "directory" else SERVICE_CONTAINER_ORDER,
        published=0,
        publication_pending=True,
    )

    crashed = _run(
        process_runner,
        case,
        env=environment(
            os.environ,
            PLATFORM_PKI_SERVICE_RECOVER_CRASH_AT=point,
        ),
    )
    assert crashed.status == 128 + signal.SIGKILL, crashed

    recovered = _run(process_runner, case)

    assert_result(recovered, 0, stderr="")
    _assert_original_destinations(case)
    _assert_private_control_final(case, "failed-pre-commit")


def test_every_recovery_checkpoint_has_a_documented_applicable_scenario(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
) -> None:
    cases: dict[str, ServiceRecoveryCase] = {}
    for name in CHECKPOINT_SCENARIOS:
        root = tmp_path / name
        root.mkdir()
        if name == "issue-precommit-created-containers":
            case = build_service_recovery_case(
                root,
                key_action=ServiceKeyAction.CREATE,
                existing_service_directories=(),
                published=-1,
            )
        elif name == "renew-precommit-existing-archive-root":
            case = _full_renewal_case(root, published=-1)
        elif name == "renew-precommit-created-archive-root":
            case = build_service_recovery_case(
                root,
                operation=ServiceOperation.RENEW,
                key_action=ServiceKeyAction.ROTATE,
                archive_members=MANAGED_RENEW_ARCHIVE_MEMBER_ORDER,
                existing_archive_root=False,
                published=-1,
            )
        elif name == "renew-publication-window":
            case = _full_renewal_case(
                root,
                published=3,
                publication_pending=True,
            )
        elif name == "issue-directory-stage-window":
            case = build_service_recovery_case(
                root,
                existing_service_directories=(),
                published=0,
                publication_pending=True,
                directory_stage_pending=True,
            )
        else:
            assert name == "renew-postcommit"
            case = _full_renewal_case(root, committed=True)
        cases[name] = case

    observed: dict[str, set[str]] = {}
    for name, case in cases.items():
        trace = tmp_path / f"{name}.trace"
        result = _run(
            process_runner,
            case,
            env=environment(
                os.environ,
                PLATFORM_PKI_SERVICE_RECOVER_TRACE_FILE=os.fspath(trace),
            ),
        )
        assert_result(result, 0, stderr="")
        observed[name] = set(trace.read_text(encoding="ascii").splitlines())

    declared = set(SERVICE_RECOVERY_CHECKPOINTS)
    assert set(CHECKPOINT_EXCLUSIONS) <= declared
    assert not (set().union(*observed.values()) - declared)
    assert set().union(*observed.values()) == declared - set(CHECKPOINT_EXCLUSIONS), {
        point: CHECKPOINT_EXCLUSIONS.get(point, "no applicable scenario observed")
        for point in sorted(declared - set().union(*observed.values()))
    }
    assert {
        "rollback-service_root-before-mutation",
        "rollback-service_private_dir-before-mutation",
    } <= observed["issue-precommit-created-containers"]
    assert {
        "archive-root-restore-before-mutation",
        "rollback-archive_key-before-mutation",
    } <= observed["renew-precommit-existing-archive-root"]
    assert "rollback-archive_root-before-mutation" in observed[
        "renew-precommit-created-archive-root"
    ]
    assert "publication-reconcile-before-journal-rewrite" in observed[
        "renew-publication-window"
    ]
    assert {
        "publication-directory-stage-discard-before-mutation",
        "publication-directory-stage-discard-after-journal-rewrite",
    } <= observed["issue-directory-stage-window"]
    assert {
        "cleanup-start-before-journal-rewrite",
        "cleanup-archive-marker-before-mutation",
    } <= observed["renew-postcommit"]


@pytest.mark.parametrize(
    "checkpoint",
    (
        "journal-loaded",
        "rollback-archive_key-before-mutation",
        "rollback-archive_key-after-mutation",
        "rollback-archive_key-evidence-after-journal-rewrite",
        "archive-root-restore-before-mutation",
        "archive-root-restore-after-mutation",
        "rollback-completion-before-mutation",
        "rollback-completion-after-mutation",
        "rollback-clear-evidence-after-journal-rewrite",
        "cleanup-stage-before-mutation",
        "cleanup-stage-after-mutation",
        "cleanup-backup-before-mutation",
        "cleanup-backup-after-mutation",
        "cleanup-terminal-before-mutation",
        "cleanup-terminal-after-mutation",
        "journal-before-mutation",
        "journal-after-mutation",
    ),
)
def test_precommit_recovery_resumes_after_crash_windows(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    checkpoint: str,
) -> None:
    case = build_service_recovery_case(
        tmp_path,
        operation=ServiceOperation.RENEW,
        key_action=ServiceKeyAction.ROTATE,
        archive_members=MANAGED_RENEW_ARCHIVE_MEMBER_ORDER,
        existing_archive_root=True,
        published=-1,
    )
    result = _run(
        process_runner,
        case,
        env=environment(
            os.environ,
            PLATFORM_PKI_SERVICE_RECOVER_CRASH_AT=checkpoint,
        ),
    )
    assert result.status == 128 + signal.SIGKILL, result

    recovered = _run(process_runner, case)

    ambiguous = {
        "rollback-completion-after-mutation": (
            "[ERROR] Rollback completion record lacks journal identity evidence\n"
        ),
        "cleanup-stage-after-mutation": (
            "[ERROR] Managed service stage_dir disappeared before cleanup\n"
        ),
        "cleanup-backup-after-mutation": (
            "[ERROR] Managed service backup_dir disappeared before cleanup\n"
        ),
        "cleanup-terminal-after-mutation": (
            "[ERROR] Managed service terminal record lacks journal identity evidence\n"
        ),
    }
    if checkpoint in ambiguous:
        assert_result(
            recovered,
            1,
            stdout="",
            stderr=ambiguous[checkpoint],
        )
        assert (case.pki / "state/service/recovery-journal").is_file()
        _assert_original_destinations(case)
        if checkpoint == "rollback-completion-after-mutation":
            assert (
                case.pki
                / f"state/service/transactions/{case.transaction}/rollback-complete"
            ).is_file()
            assert Path(case.values["stage_dir"]).is_dir()
        elif checkpoint == "cleanup-stage-after-mutation":
            assert not Path(case.values["stage_dir"]).exists()
            assert Path(case.values["backup_dir"]).is_dir()
        elif checkpoint == "cleanup-backup-after-mutation":
            assert not Path(case.values["backup_dir"]).exists()
            assert not Path(case.values["terminal_path"]).exists()
        else:
            assert Path(case.values["terminal_path"]).is_file()
        return

    expected = (
        "[OK] Managed service transaction already recovered: app "
        "(failed-pre-commit)\n"
        if checkpoint == "journal-after-mutation"
        else "[OK] Recovered managed service transaction: app (failed-pre-commit)\n"
    )
    assert_result(recovered, 0, stdout=expected, stderr="")
    _assert_original_destinations(case)
    _assert_private_control_final(case, "failed-pre-commit")


@pytest.mark.parametrize(
    "checkpoint",
    (
        "cleanup-archive-marker-before-mutation",
        "cleanup-archive-marker-after-mutation",
        "cleanup-stage-after-mutation",
        "cleanup-backup-after-mutation",
        "cleanup-terminal-after-mutation",
        "journal-after-mutation",
    ),
)
def test_committed_cleanup_resumes_after_crash_windows(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    checkpoint: str,
) -> None:
    case = _full_renewal_case(tmp_path, committed=True)
    destinations = {
        mutation.key: Path(mutation.destination).read_bytes()
        for mutation in _record(case).mutations
        if mutation.stage is not None and mutation.key != "archive_marker"
    }

    crashed = _run(
        process_runner,
        case,
        env=environment(
            os.environ,
            PLATFORM_PKI_SERVICE_RECOVER_CRASH_AT=checkpoint,
        ),
    )
    assert crashed.status == 128 + signal.SIGKILL, crashed

    recovered = _run(process_runner, case)

    ambiguous = {
        "cleanup-archive-marker-after-mutation": (
            "[ERROR] Published service destination archive_marker identity changed\n"
        ),
        "cleanup-stage-after-mutation": (
            "[ERROR] Managed service stage_dir disappeared before cleanup\n"
        ),
        "cleanup-backup-after-mutation": (
            "[ERROR] Managed service backup_dir disappeared before cleanup\n"
        ),
        "cleanup-terminal-after-mutation": (
            "[ERROR] Managed service terminal record lacks journal identity evidence\n"
        ),
    }
    if checkpoint in ambiguous:
        assert_result(
            recovered,
            1,
            stdout="",
            stderr=ambiguous[checkpoint],
        )
        assert (case.pki / "state/service/recovery-journal").is_file()
        if checkpoint == "cleanup-archive-marker-after-mutation":
            assert not Path(case.values["archive_marker_destination"]).exists()
            assert Path(case.values["stage_dir"]).is_dir()
        elif checkpoint == "cleanup-stage-after-mutation":
            assert not Path(case.values["stage_dir"]).exists()
            assert Path(case.values["backup_dir"]).is_dir()
        elif checkpoint == "cleanup-backup-after-mutation":
            assert not Path(case.values["backup_dir"]).exists()
            assert not Path(case.values["terminal_path"]).exists()
        else:
            assert Path(case.values["terminal_path"]).is_file()
        return

    assert_result(recovered, 0, stderr="")
    for key, data in destinations.items():
        assert Path(case.values[f"{key}_destination"]).read_bytes() == data
    _assert_private_control_final(case, "succeeded")


@pytest.mark.parametrize(
    ("variable", "status"),
    (
        ("PLATFORM_PKI_SERVICE_RECOVER_SIGNAL_AT", 128 + signal.SIGTERM),
        ("PLATFORM_PKI_SERVICE_RECOVER_FAILURE_AT", 1),
    ),
)
def test_recovery_resumes_after_signal_and_injected_failure(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    variable: str,
    status: int,
) -> None:
    case = _full_renewal_case(tmp_path, published=-1)
    interrupted = _run(
        process_runner,
        case,
        env=environment(os.environ, **{variable: "rollback-archive_key-after-mutation"}),
    )
    assert interrupted.status == status, interrupted

    recovered = _run(process_runner, case)

    assert_result(recovered, 0, stderr="")
    _assert_original_destinations(case)
    _assert_private_control_final(case, "failed-pre-commit")


@pytest.mark.parametrize(
    "target",
    ("journal", "transaction", "input", "stage", "backup", "destination"),
)
def test_recovery_rejects_same_content_identity_replacement(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    target: str,
) -> None:
    case = build_service_recovery_case(tmp_path)
    record = _record(case)
    paths = {
        "journal": case.pki / "state/service/recovery-journal",
        "transaction": Path(record["transaction_record_path"]),
        "input": Path(record["signing_inventory_source"]),
        "stage": Path(record["service_config_stage"]),
        "backup": Path(record["ca_index_backup"]),
        "destination": Path(record["ca_index_destination"]),
    }
    path = paths[target]
    replacement = path.with_name(f".{path.name}.replacement")
    replacement.write_bytes(path.read_bytes())
    replacement.chmod(path.stat().st_mode & 0o777)
    os.replace(replacement, path)

    result = _run(process_runner, case)

    assert result.status == 1
    assert result.stdout == ""
    assert result.stderr.startswith("[ERROR] ")


def test_recovery_rejects_incompatible_state_without_mutation(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
) -> None:
    case = build_service_recovery_case(tmp_path, published=3)
    before = (case.pki / "state/service/recovery-journal").read_bytes()
    incompatible = case.pki / "state/csr/recovery-journal"
    incompatible.parent.mkdir(parents=True, exist_ok=True)
    incompatible.write_bytes(b"blocked\n")

    result = _run(process_runner, case)

    assert_result(
        result,
        1,
        stdout="",
        stderr="[ERROR] CSR signing recovery must be completed before managed service recovery\n",
    )
    assert (case.pki / "state/service/recovery-journal").read_bytes() == before


def test_recovery_rejects_backup_loss_before_its_cleanup_window(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
) -> None:
    case = _full_renewal_case(tmp_path, published=-1)
    crashed = _run(
        process_runner,
        case,
        env=environment(
            os.environ,
            PLATFORM_PKI_SERVICE_RECOVER_CRASH_AT="cleanup-stage-before-mutation",
        ),
    )
    assert crashed.status == 128 + signal.SIGKILL, crashed
    shutil.rmtree(Path(case.values["backup_dir"]))

    result = _run(process_runner, case)

    assert_result(
        result,
        1,
        stdout="",
        stderr="[ERROR] Managed service backup_dir disappeared before cleanup\n",
    )


def test_recovery_rejects_unexpected_private_stage_entry(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
) -> None:
    case = build_service_recovery_case(tmp_path)
    unexpected = Path(case.values["stage_dir"]) / "unexpected-secret"
    unexpected.write_bytes(b"do not disclose this content")
    unexpected.chmod(0o600)

    result = _run(process_runner, case)

    assert_result(
        result,
        1,
        stdout="",
        stderr="[ERROR] Managed service stage has unexpected entries\n",
    )


@pytest.mark.parametrize(
    ("variant", "key"),
    (
        ("absent-file", "archive_key"),
        ("existing-file", "ca_serial"),
        ("absent-directory", "service_certs_dir"),
    ),
)
def test_rollback_rejects_same_name_replacement_at_mutation_boundary(
    tmp_path: Path,
    process_starter: Callable[..., ManagedProcess],
    variant: str,
    key: str,
) -> None:
    case = (
        build_service_recovery_case(
            tmp_path,
            operation=ServiceOperation.ISSUE,
            key_action=ServiceKeyAction.CREATE,
            existing_service_directories=(),
            published=-1,
        )
        if variant == "absent-directory"
        else _full_renewal_case(tmp_path, published=-1)
    )
    record = _record(case)
    rollback_order = managed_rollback_order(record.publication_order)
    next_key = rollback_order[rollback_order.index(key) + 1]
    next_destination = Path(case.values[f"{next_key}_destination"])
    process, release = _start_paused(
        process_starter,
        case,
        tmp_path,
        f"rollback-{key}-before-mutation",
    )
    destination = Path(case.values[f"{key}_destination"])
    next_before = identity_at(next_destination)
    if variant == "absent-directory":
        assert not any(destination.iterdir())
        original = destination.with_name(f".{destination.name}.race-original")
        destination.rename(original)
        destination.mkdir(mode=0o700)
        replacement = _live_file(destination)
    else:
        replacement = _replace_file(destination)
    release.write_bytes(b"release\n")

    result = process.wait()

    assert result.status == 1
    assert _live_file(destination) == replacement
    assert identity_at(next_destination) == next_before
    assert (case.pki / "state/service/recovery-journal").is_file()


@pytest.mark.parametrize("target", ("stage", "backup", "marker"))
def test_cleanup_rejects_allowed_member_replacement_at_mutation_boundary(
    tmp_path: Path,
    process_starter: Callable[..., ManagedProcess],
    target: str,
) -> None:
    if target == "stage":
        case = _full_renewal_case(tmp_path, staged_count=1)
        point = "cleanup-stage-before-mutation"
        path = Path(case.values["signing_inventory_stage"])
        guard = Path(case.values["backup_dir"])
    elif target == "backup":
        case = _full_renewal_case(tmp_path, committed=True)
        point = "cleanup-backup-before-mutation"
        path = Path(case.values["ca_index_backup"])
        guard = Path(case.values["terminal_path"])
    else:
        case = _full_renewal_case(tmp_path, committed=True)
        point = "cleanup-archive-marker-before-mutation"
        path = Path(case.values["archive_marker_destination"])
        guard = Path(case.values["stage_dir"])
    process, release = _start_paused(
        process_starter,
        case,
        tmp_path,
        point,
    )
    guard_before = identity_at(guard)
    replacement = _replace_file(path)
    release.write_bytes(b"release\n")

    result = process.wait()

    assert result.status == 1
    assert _live_file(path) == replacement
    assert identity_at(guard) == guard_before
    assert (case.pki / "state/service/recovery-journal").is_file()


@pytest.mark.parametrize("window", ("before", "after"))
def test_terminal_publication_rejects_same_name_replacement(
    tmp_path: Path,
    process_starter: Callable[..., ManagedProcess],
    window: str,
) -> None:
    case = build_service_recovery_case(tmp_path, committed=True)
    record = _record(case)
    expected = serialize_service_retained_terminal(
        {
            "schema": "1",
            "transaction": record["transaction"],
            "operation": record["operation"],
            "service": record["service"],
            "outcome": record["outcome"],
            "committed": record["committed"],
            "transaction_identity": record["transaction_record_identity"],
            "transaction_sha256": record["transaction_record_sha256"],
            "rollback_completion_identity": record[
                "rollback_completion_identity"
            ],
            "rollback_completion_sha256": record[
                "rollback_completion_sha256"
            ],
        }
    )
    process, release = _start_paused(
        process_starter,
        case,
        tmp_path,
        f"cleanup-terminal-{window}-mutation",
    )
    terminal = Path(case.values["terminal_path"])
    if window == "before":
        terminal.write_bytes(expected)
        terminal.chmod(0o600)
        replacement = _live_file(terminal)
    else:
        replacement = _replace_file(terminal)
    release.write_bytes(b"release\n")

    result = process.wait()

    assert result.status == 1
    assert _live_file(terminal) == replacement
    assert terminal.read_bytes() == expected
    assert (case.pki / "state/service/recovery-journal").is_file()


def test_journal_cleanup_rejects_same_name_replacement(
    tmp_path: Path,
    process_starter: Callable[..., ManagedProcess],
) -> None:
    case = build_service_recovery_case(tmp_path, committed=True)
    process, release = _start_paused(
        process_starter,
        case,
        tmp_path,
        "journal-before-mutation",
    )
    journal = case.pki / "state/service/recovery-journal"
    terminal = Path(case.values["terminal_path"])
    terminal_before = _live_file(terminal)
    replacement = _replace_file(journal)
    release.write_bytes(b"release\n")

    result = process.wait()

    assert result.status == 1
    assert _live_file(journal) == replacement
    assert _live_file(terminal) == terminal_before


@pytest.mark.parametrize("target", ("transaction", "terminal", "rollback-complete"))
def test_journal_cleanup_reauthenticates_retained_evidence(
    tmp_path: Path,
    process_starter: Callable[..., ManagedProcess],
    target: str,
) -> None:
    case = build_service_recovery_case(
        tmp_path,
        committed=target != "rollback-complete",
        published=0 if target == "rollback-complete" else None,
    )
    process, release = _start_paused(
        process_starter,
        case,
        tmp_path,
        "journal-before-mutation",
    )
    transaction_dir = (
        case.pki / f"state/service/transactions/{case.transaction}"
    )
    evidence = transaction_dir / target
    replacement = _replace_file(evidence)
    release.write_bytes(b"release\n")

    result = process.wait()

    assert result.status == 1
    assert _live_file(evidence) == replacement
    assert (case.pki / "state/service/recovery-journal").is_file()


def _recreate_cleanup_name(path: Path, kind: str, root: Path) -> None:
    if kind == "file":
        path.write_bytes(b"hostile cleanup reappearance\n")
        path.chmod(0o600)
    elif kind == "directory":
        path.mkdir(mode=0o700)
    else:
        target = root / f"{path.name}-symlink-target"
        target.write_bytes(b"external sentinel\n")
        path.symlink_to(target)


def _assert_cleanup_name_untouched(path: Path, kind: str) -> None:
    if kind == "file":
        assert path.is_file() and not path.is_symlink()
        assert path.read_bytes() == b"hostile cleanup reappearance\n"
    elif kind == "directory":
        assert path.is_dir() and not path.is_symlink()
    else:
        assert path.is_symlink()
        assert path.resolve().read_bytes() == b"external sentinel\n"


@pytest.mark.parametrize("target", ("stage", "backup", "archive-marker"))
@pytest.mark.parametrize("kind", ("file", "directory", "symlink"))
def test_journal_cleanup_rejects_cleanup_name_reappearance(
    tmp_path: Path,
    process_starter: Callable[..., ManagedProcess],
    target: str,
    kind: str,
) -> None:
    case = _full_renewal_case(tmp_path, committed=True)
    process, release = _start_paused(
        process_starter,
        case,
        tmp_path,
        "journal-before-mutation",
    )
    path = (
        Path(case.values["archive_marker_destination"])
        if target == "archive-marker"
        else Path(case.values[f"{target}_dir"])
    )
    _recreate_cleanup_name(path, kind, tmp_path)
    release.write_bytes(b"release\n")

    result = process.wait()

    assert result.status == 1
    assert (case.pki / "state/service/recovery-journal").is_file()
    _assert_cleanup_name_untouched(path, kind)


@pytest.mark.parametrize(
    ("operation", "committed", "outcome"),
    (
        (ServiceOperation.ISSUE, False, "failed-pre-commit"),
        (ServiceOperation.RENEW, False, "failed-pre-commit"),
        (ServiceOperation.ISSUE, True, "succeeded"),
        (ServiceOperation.RENEW, True, "succeeded"),
    ),
)
def test_already_recovered_accepts_every_operation_outcome_cleanup_set(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    operation: ServiceOperation,
    committed: bool,
    outcome: str,
) -> None:
    case = build_service_recovery_case(
        tmp_path,
        operation=operation,
        committed=committed,
        published=None if committed else 0,
    )
    assert_result(_run(process_runner, case), 0, stderr="")

    repeated = _run(process_runner, case)

    assert_result(
        repeated,
        0,
        stdout=(
            "[OK] Managed service transaction already recovered: "
            f"app ({outcome})\n"
        ),
        stderr="",
    )


@pytest.mark.parametrize(
    ("operation", "committed"),
    (
        (ServiceOperation.ISSUE, False),
        (ServiceOperation.RENEW, False),
        (ServiceOperation.ISSUE, True),
        (ServiceOperation.RENEW, True),
    ),
)
@pytest.mark.parametrize("target", ("stage", "backup"))
def test_already_recovered_rejects_applicable_private_cleanup_reappearance(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    operation: ServiceOperation,
    committed: bool,
    target: str,
) -> None:
    case = build_service_recovery_case(
        tmp_path,
        operation=operation,
        committed=committed,
        published=None if committed else 0,
    )
    assert_result(_run(process_runner, case), 0, stderr="")
    path = Path(case.values[f"{target}_dir"])
    _recreate_cleanup_name(path, "file", tmp_path)

    result = _run(process_runner, case)

    assert result.status == 1
    _assert_cleanup_name_untouched(path, "file")


@pytest.mark.parametrize("kind", ("file", "directory", "symlink"))
def test_already_recovered_successful_renewal_rejects_marker_reappearance(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    kind: str,
) -> None:
    case = _full_renewal_case(tmp_path, committed=True)
    assert_result(_run(process_runner, case), 0, stderr="")
    marker = Path(case.values["archive_marker_destination"])
    _recreate_cleanup_name(marker, kind, tmp_path)

    result = _run(process_runner, case)

    assert result.status == 1
    _assert_cleanup_name_untouched(marker, kind)


@pytest.mark.parametrize(
    ("operation", "committed"),
    (
        (ServiceOperation.ISSUE, False),
        (ServiceOperation.RENEW, False),
        (ServiceOperation.ISSUE, True),
    ),
)
def test_already_recovered_does_not_infer_nonapplicable_marker(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    operation: ServiceOperation,
    committed: bool,
) -> None:
    case = build_service_recovery_case(
        tmp_path,
        operation=operation,
        committed=committed,
        published=None if committed else 0,
    )
    assert_result(_run(process_runner, case), 0, stderr="")
    if operation is ServiceOperation.RENEW:
        marker = Path(case.values["archive_marker_destination"])
    else:
        marker = case.pki / "services/app/archive/current/.platform-pki-renew-archive"
    marker.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _recreate_cleanup_name(marker, "file", tmp_path)

    repeated = _run(process_runner, case)

    assert_result(repeated, 0, stderr="")
    _assert_cleanup_name_untouched(marker, "file")


@pytest.mark.parametrize("target", ("transaction", "rollback-complete"))
def test_already_recovered_rejects_same_name_evidence_replacement(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    target: str,
) -> None:
    case = build_service_recovery_case(tmp_path, published=0)
    assert_result(_run(process_runner, case), 0, stderr="")
    evidence = (
        case.pki
        / f"state/service/transactions/{case.transaction}/{target}"
    )
    replacement = _replace_file(evidence)

    result = _run(process_runner, case)

    assert result.status == 1
    assert _live_file(evidence) == replacement


@pytest.mark.parametrize("target", ("transaction", "terminal", "rollback-complete"))
def test_already_recovered_requires_private_evidence_modes(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    target: str,
) -> None:
    case = build_service_recovery_case(
        tmp_path,
        committed=target != "rollback-complete",
        published=0 if target == "rollback-complete" else None,
    )
    assert_result(_run(process_runner, case), 0, stderr="")
    evidence = (
        case.pki
        / f"state/service/transactions/{case.transaction}/{target}"
    )
    evidence.chmod(0o644)

    result = _run(process_runner, case)

    assert result.status == 1
    assert evidence.stat().st_mode & 0o777 == 0o644


def test_already_recovered_success_rejects_unclaimed_rollback_completion(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
) -> None:
    case = build_service_recovery_case(tmp_path, committed=True)
    assert_result(_run(process_runner, case), 0, stderr="")
    rollback = (
        case.pki
        / f"state/service/transactions/{case.transaction}/rollback-complete"
    )
    rollback.write_bytes(b"unclaimed\n")
    rollback.chmod(0o600)

    result = _run(process_runner, case)

    assert result.status == 1
    assert rollback.read_bytes() == b"unclaimed\n"


@pytest.mark.parametrize("replacement", ("entry", "root"))
def test_cleanup_rechecks_private_tree_at_the_mutation_boundary(
    tmp_path: Path,
    process_starter: Callable[..., ManagedProcess],
    replacement: str,
) -> None:
    case = _full_renewal_case(tmp_path, committed=True)
    marker = tmp_path / "cleanup-paused"
    release = tmp_path / "cleanup-release"
    process = process_starter(
        [
            sys.executable,
            DRIVER,
            "--pki-dir",
            case.pki,
            "--transaction",
            case.transaction,
        ],
        env=environment(
            os.environ,
            PLATFORM_PKI_SERVICE_RECOVER_PAUSE_AT="cleanup-stage-before-mutation",
            PLATFORM_PKI_SERVICE_RECOVER_PAUSE_MARKER=os.fspath(marker),
            PLATFORM_PKI_SERVICE_RECOVER_PAUSE_RELEASE=os.fspath(release),
        ),
        timeout=120,
    )
    deadline = time.monotonic() + 10
    while not marker.exists() and process.observe().status is None and time.monotonic() < deadline:
        time.sleep(0.02)
    assert marker.exists(), process.observe()
    stage = Path(case.values["stage_dir"])
    backup_before = _live_file(Path(case.values["backup_dir"]))
    replacement_identity = None
    if replacement == "entry":
        unexpected = stage / "unexpected"
        unexpected.write_bytes(b"unexpected private content")
        unexpected.chmod(0o600)
    else:
        original = stage.with_name("stage-replaced")
        stage.rename(original)
        shutil.copytree(original, stage)
        replacement_identity = _live_file(stage)
    release.write_bytes(b"release\n")

    result = process.wait()

    assert result.status == 1
    assert result.stdout == ""
    assert result.stderr.startswith("[ERROR] Managed service ")
    if replacement_identity is not None:
        assert _live_file(stage) == replacement_identity
    assert _live_file(Path(case.values["backup_dir"])) == backup_before
    assert (case.pki / "state/service/recovery-journal").is_file()


def test_recovery_diagnostics_do_not_disclose_changed_input(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
) -> None:
    case = build_service_recovery_case(tmp_path)
    record = _record(case)
    secret = "managed-service-secret-value"
    Path(record["signing_inventory_source"]).write_text(secret, encoding="ascii")

    result = _run(process_runner, case)

    assert result.status == 1
    assert secret not in result.stdout
    assert secret not in result.stderr


def test_recovery_holds_the_full_inventory_lock_chain(
    tmp_path: Path,
    process_starter: Callable[..., ManagedProcess],
) -> None:
    case = build_service_recovery_case(tmp_path)
    marker = tmp_path / "paused"
    release = tmp_path / "release"
    process = process_starter(
        [
            sys.executable,
            DRIVER,
            "--pki-dir",
            case.pki,
            "--transaction",
            case.transaction,
        ],
        env=environment(
            os.environ,
            PLATFORM_PKI_SERVICE_RECOVER_PAUSE_AT="journal-loaded",
            PLATFORM_PKI_SERVICE_RECOVER_PAUSE_MARKER=os.fspath(marker),
            PLATFORM_PKI_SERVICE_RECOVER_PAUSE_RELEASE=os.fspath(release),
        ),
        timeout=120,
    )
    deadline = time.monotonic() + 10
    while not marker.exists() and process.observe().status is None and time.monotonic() < deadline:
        time.sleep(0.02)
    assert marker.exists(), process.observe()
    streams = []
    try:
        for name in ("lifecycle", "root", "intermediate", "inventory"):
            stream = (case.pki / f"locks/{name}").open("r+")
            streams.append(stream)
            with pytest.raises(BlockingIOError):
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        for stream in streams:
            stream.close()
        release.write_bytes(b"release\n")
    assert_result(process.wait(), 0, stderr="")
