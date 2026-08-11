from __future__ import annotations

import os
import shutil
import signal
import sys
import time
from collections.abc import Callable
from pathlib import Path

import pytest

from src.platform_pki.errors import ApplicationError
from src.platform_pki.faults import FaultHook, InjectedFaultError
from src.platform_pki.filesystem import DirectoryIdentity, FileIdentity
from src.platform_pki.service_recover import recover_service_transaction
from src.platform_pki.service_transaction import (
    ServiceKeyAction,
    ServicePhase,
    parse_service_transaction,
)
from src.platform_pki.service_writer import (
    ManagedServiceWriter,
)

from ..harness import ManagedProcess, ProcessResult
from .service_recover_case import build_service_recovery_case
from .support import environment


pytestmark = pytest.mark.pki
REPOSITORY = Path(__file__).resolve().parents[2]
DRIVER = REPOSITORY / "tests/pki/service_writer_driver.py"


def _record(case):
    journal = case.pki / "state/service/recovery-journal"
    return parse_service_transaction(journal.read_bytes(), pki_dir=case.pki)


def _start_paused(
    process_starter: Callable[..., ManagedProcess],
    case,
    tmp_path: Path,
    point: str,
) -> tuple[ManagedProcess, Path]:
    marker = tmp_path / "writer-paused"
    release = tmp_path / "writer-release"
    process = process_starter(
        [sys.executable, DRIVER, "--pki-dir", case.pki],
        env=environment(
            os.environ,
            PLATFORM_PKI_SERVICE_WRITER_PAUSE_AT=point,
            PLATFORM_PKI_SERVICE_WRITER_PAUSE_MARKER=os.fspath(marker),
            PLATFORM_PKI_SERVICE_WRITER_PAUSE_RELEASE=os.fspath(release),
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


def _run_with_signal(
    process_runner: Callable[..., ProcessResult],
    case,
    point: str,
) -> ProcessResult:
    return process_runner(
        [sys.executable, DRIVER, "--pki-dir", case.pki],
        env=environment(
            os.environ,
            PLATFORM_PKI_SERVICE_WRITER_SIGNAL_AT=point,
        ),
        timeout=120,
    )


def _run_with_crash(
    process_runner: Callable[..., ProcessResult],
    case,
    point: str,
) -> ProcessResult:
    return process_runner(
        [sys.executable, DRIVER, "--pki-dir", case.pki],
        env=environment(
            os.environ,
            PLATFORM_PKI_SERVICE_WRITER_CRASH_AT=point,
        ),
        timeout=120,
    )


def _replace_file(path: Path) -> bytes:
    data = path.read_bytes()
    replacement = path.with_name(f".{path.name}.writer-race")
    replacement.write_bytes(data)
    replacement.chmod(path.stat().st_mode & 0o777)
    os.replace(replacement, path)
    return data


def _create_writer(tmp_path: Path) -> ManagedServiceWriter:
    case = build_service_recovery_case(tmp_path, published=0)
    journal = case.pki / "state/service/recovery-journal"
    journal.unlink()
    return ManagedServiceWriter.create(case.values, pki_dir=case.pki)


def _replace_case_journal(case) -> ManagedServiceWriter:
    journal = case.pki / "state/service/recovery-journal"
    journal.unlink()
    return ManagedServiceWriter.create(case.values, pki_dir=case.pki)


def test_writer_publishes_a_self_bound_parser_valid_journal(tmp_path: Path) -> None:
    writer = _create_writer(tmp_path)

    data = Path(writer.path).read_bytes()
    record = parse_service_transaction(data, pki_dir=writer.pki_dir)

    assert record.phase is ServicePhase.PLANNED
    assert record.identity("journal_identity") == writer.identity.state
    assert ManagedServiceWriter.load(
        writer.path, pki_dir=writer.pki_dir
    ).record.to_bytes() == data


def test_writer_rejects_out_of_order_publication(tmp_path: Path) -> None:
    writer = _create_writer(tmp_path)

    with pytest.raises(ValueError, match="out of order"):
        writer.begin_publication(writer.record.publication_order[1])


def test_writer_does_not_resume_a_recovery_publication_window(tmp_path: Path) -> None:
    case = build_service_recovery_case(
        tmp_path,
        published=0,
        publication_pending=True,
    )
    writer = ManagedServiceWriter.load(
        case.pki / "state/service/recovery-journal",
        pki_dir=case.pki,
    )
    key = writer.record.publication_order[0]
    destination = Path(case.values[f"{key}_destination"])
    before = destination.read_bytes()

    with pytest.raises(ValueError, match="requires recovery"):
        writer.publish_next()

    assert _record(case)["checkpoint"] == "publication-pending"
    assert destination.read_bytes() == before


def test_initial_publication_fault_retains_a_parser_valid_journal(
    tmp_path: Path,
) -> None:
    case = build_service_recovery_case(tmp_path, published=0)
    journal = case.pki / "state/service/recovery-journal"
    journal.unlink()

    with pytest.raises(InjectedFaultError):
        ManagedServiceWriter.create(
            case.values,
            pki_dir=case.pki,
            fault=FaultHook(failure_at="journal-after-mutation"),
        )

    record = parse_service_transaction(journal.read_bytes(), pki_dir=case.pki)
    assert record.phase is ServicePhase.PLANNED


def test_rewrite_fault_retains_the_new_parser_valid_checkpoint(
    tmp_path: Path,
) -> None:
    writer = _create_writer(tmp_path)
    key = writer.record.publication_order[0]
    writer.fault = FaultHook(
        failure_at=f"publish-{key}-pending-after-journal-rewrite"
    )

    with pytest.raises(InjectedFaultError):
        writer.begin_publication(key)

    record = parse_service_transaction(
        Path(writer.path).read_bytes(), pki_dir=writer.pki_dir
    )
    assert record.phase is ServicePhase.PUBLISHING
    assert record["checkpoint"] == "publication-pending"
    assert record["mutation"] == key


def test_writer_rejects_replaced_journal_identity(tmp_path: Path) -> None:
    writer = _create_writer(tmp_path)
    journal = Path(writer.path)
    replacement = journal.with_name("replacement")
    replacement.write_bytes(journal.read_bytes())
    replacement.chmod(0o600)
    os.replace(replacement, journal)

    with pytest.raises(ApplicationError, match="identity changed"):
        writer.begin_publication(writer.record.publication_order[0])


def test_writer_records_staging_as_an_exact_prefix(tmp_path: Path) -> None:
    case = build_service_recovery_case(tmp_path, staged_count=0)
    writer = _replace_case_journal(case)
    first, second = writer.record.staging_order[:2]
    assert writer.record["mutation"] == first

    source = Path(writer.values[f"{first}_source"])
    stage = Path(writer.values[f"{first}_stage"])
    shutil.copy2(source, stage)
    stage.chmod(0o600)
    writer.record_staging(first)
    pending = writer.begin_staging(second)

    assert pending.phase is ServicePhase.STAGING
    assert pending["checkpoint"] == "staging-pending"
    assert pending["mutation"] == second
    assert pending["staged_count"] == "1"


def test_writer_records_private_backups_as_an_exact_prefix(tmp_path: Path) -> None:
    case = build_service_recovery_case(tmp_path, backed_up_count=0)
    writer = _replace_case_journal(case)
    first, second = writer.record.backup_order[:2]
    assert writer.record["mutation"] == first

    shutil.copy2(
        writer.values[f"{first}_destination"],
        writer.values[f"{first}_backup"],
    )
    writer.record_backup(first)
    pending = writer.begin_backup(second)

    assert pending.phase is ServicePhase.BACKING_UP
    assert pending["checkpoint"] == "backup-pending"
    assert pending["mutation"] == second
    assert pending["backed_up_count"] == "1"


def test_committed_journal_is_accepted_when_shared_recovery_is_invoked(
    tmp_path: Path,
) -> None:
    writer = _create_writer(tmp_path)

    while int(writer.record["published_count"]) < len(
        writer.record.publication_order
    ):
        writer.publish_next()

    writer.begin_verification()
    writer.finish_verification()
    committed = writer.commit()

    assert committed.phase is ServicePhase.COMMITTED
    assert committed["committed"] == "true"
    assert committed["recovery_mode"] == "cleanup-only"
    assert committed["published_count"] == str(len(committed.publication_order))
    assert recover_service_transaction(
        writer.pki_dir,
        transaction=committed["transaction"],
    ) == 0
    transaction = Path(committed["transaction_dir"])
    assert not Path(writer.path).exists()
    assert not (transaction / "stage").exists()
    assert not (transaction / "backup").exists()
    assert (transaction / "terminal").is_file()


def test_publication_fault_after_mutation_is_recovered_without_republishing(
    tmp_path: Path,
) -> None:
    case = build_service_recovery_case(tmp_path, published=0)
    writer = _replace_case_journal(case)
    key = "ca_index"
    while writer.record.publication_order[
        int(writer.record["published_count"])
    ] != key:
        writer.publish_next()
    destination = Path(writer.values[f"{key}_destination"])
    original = destination.read_bytes()
    writer.fault = FaultHook(failure_at=f"publish-{key}-after-publication")

    with pytest.raises(InjectedFaultError):
        writer.publish_next()

    pending = parse_service_transaction(
        Path(writer.path).read_bytes(), pki_dir=writer.pki_dir
    )
    assert pending.phase is ServicePhase.PUBLISHING
    assert pending["checkpoint"] == "publication-pending"
    assert pending["mutation"] == key
    assert destination.read_bytes() != original
    assert recover_service_transaction(
        writer.pki_dir,
        transaction=pending["transaction"],
    ) == 0
    assert destination.read_bytes() == original


def test_publish_next_creates_planned_archive_directories(tmp_path: Path) -> None:
    case = build_service_recovery_case(
        tmp_path,
        key_action=ServiceKeyAction.ROTATE,
        existing_archive_root=False,
        published=0,
    )
    writer = _replace_case_journal(case)

    while writer.record.publication_order[
        int(writer.record["published_count"])
    ] != "archive_root":
        writer.publish_next()
    writer.publish_next()
    writer.publish_next()

    archive_root = Path(writer.values["archive_root_destination"])
    archive_dir = Path(writer.values["archive_dir_destination"])
    assert archive_root.is_dir()
    assert archive_dir.is_dir()
    assert archive_root.stat().st_mode & 0o777 == 0o700
    assert archive_dir.stat().st_mode & 0o777 == 0o700


def test_preflight_rejects_same_name_stage_replacement(
    tmp_path: Path,
    process_starter: Callable[..., ManagedProcess],
) -> None:
    case = build_service_recovery_case(tmp_path, published=0)
    key = _record(case).publication_order[0]
    stage = Path(case.values[f"{key}_stage"])
    destination = Path(case.values[f"{key}_destination"])
    process, release = _start_paused(
        process_starter,
        case,
        tmp_path,
        f"publish-{key}-before-publication",
    )
    foreign = _replace_file(stage)
    release.write_bytes(b"")

    result = process.wait()
    assert result.status == 1, result
    assert stage.read_bytes() == foreign
    assert not destination.exists()
    pending = _record(case)
    assert pending["checkpoint"] == "publication-pending"
    assert pending["published_count"] == "0"
    with pytest.raises(ApplicationError):
        recover_service_transaction(case.pki, transaction=case.transaction)
    assert stage.read_bytes() == foreign
    assert (case.pki / "state/service/recovery-journal").is_file()


def test_preflight_rejects_same_name_control_journal_replacement(
    tmp_path: Path,
    process_starter: Callable[..., ManagedProcess],
) -> None:
    case = build_service_recovery_case(tmp_path, published=0)
    key = _record(case).publication_order[0]
    journal = case.pki / "state/service/recovery-journal"
    destination = Path(case.values[f"{key}_destination"])
    process, release = _start_paused(
        process_starter,
        case,
        tmp_path,
        f"publish-{key}-before-publication",
    )
    foreign = _replace_file(journal)
    release.write_bytes(b"")

    result = process.wait()
    assert result.status == 1, result
    assert journal.read_bytes() == foreign
    assert not destination.exists()
    assert _record(case)["published_count"] == "0"
    with pytest.raises(ApplicationError):
        recover_service_transaction(case.pki, transaction=case.transaction)
    assert journal.read_bytes() == foreign


def test_preflight_rejects_destination_pre_state_replacement(
    tmp_path: Path,
    process_starter: Callable[..., ManagedProcess],
) -> None:
    case = build_service_recovery_case(tmp_path, published=6)
    record = _record(case)
    key = record.publication_order[6]
    assert key == "ca_index"
    destination = Path(case.values[f"{key}_destination"])
    stage = Path(case.values[f"{key}_stage"])
    process, release = _start_paused(
        process_starter,
        case,
        tmp_path,
        f"publish-{key}-before-publication",
    )
    foreign = _replace_file(destination)
    release.write_bytes(b"")

    result = process.wait()
    assert result.status == 1, result
    assert destination.read_bytes() == foreign
    assert stage.is_file()
    assert _record(case)["published_count"] == "6"
    with pytest.raises(ApplicationError):
        recover_service_transaction(case.pki, transaction=case.transaction)
    assert destination.read_bytes() == foreign
    assert (case.pki / "state/service/recovery-journal").is_file()


def test_preflight_rejects_planned_parent_replacement(
    tmp_path: Path,
    process_starter: Callable[..., ManagedProcess],
) -> None:
    case = build_service_recovery_case(tmp_path, published=0)
    record = _record(case)
    key = record.publication_order[0]
    destination = Path(case.values[f"{key}_destination"])
    parent = destination.parent
    displaced = parent.with_name("app-displaced")
    process, release = _start_paused(
        process_starter,
        case,
        tmp_path,
        f"publish-{key}-before-publication",
    )
    os.replace(parent, displaced)
    shutil.copytree(displaced, parent)
    release.write_bytes(b"")

    result = process.wait()
    assert result.status == 1, result
    assert parent.is_dir()
    assert not destination.exists()
    assert Path(case.values[f"{key}_stage"]).is_file()
    assert _record(case)["published_count"] == "0"
    assert recover_service_transaction(case.pki, transaction=case.transaction) == 0
    assert parent.is_dir()
    assert displaced.is_dir()
    assert not (case.pki / "state/service/recovery-journal").exists()


def test_preflight_rejects_no_clobber_destination_appearance(
    tmp_path: Path,
    process_starter: Callable[..., ManagedProcess],
) -> None:
    case = build_service_recovery_case(tmp_path, published=0)
    record = _record(case)
    key = record.publication_order[0]
    destination = Path(case.values[f"{key}_destination"])
    process, release = _start_paused(
        process_starter,
        case,
        tmp_path,
        f"publish-{key}-before-publication",
    )
    foreign = b"foreign no-clobber destination\n"
    destination.write_bytes(foreign)
    destination.chmod(0o600)
    release.write_bytes(b"")

    result = process.wait()
    assert result.status == 1, result
    assert destination.read_bytes() == foreign
    assert Path(case.values[f"{key}_stage"]).is_file()
    assert _record(case)["published_count"] == "0"
    with pytest.raises(ApplicationError):
        recover_service_transaction(case.pki, transaction=case.transaction)
    assert destination.read_bytes() == foreign
    assert (case.pki / "state/service/recovery-journal").is_file()


@pytest.mark.parametrize(
    "evidence",
    (
        "retained-transaction",
        "inventory",
        "signing-input",
        "backup",
        "prior-publication",
    ),
)
def test_preflight_reauthenticates_transaction_wide_file_evidence(
    tmp_path: Path,
    evidence: str,
) -> None:
    case = build_service_recovery_case(
        tmp_path,
        published=1 if evidence == "prior-publication" else 0,
    )
    writer = ManagedServiceWriter.load(
        case.pki / "state/service/recovery-journal",
        pki_dir=case.pki,
    )
    if evidence == "retained-transaction":
        stale = Path(case.values["transaction_record_path"])
    elif evidence == "inventory":
        stale = Path(case.values["signing_inventory_source"])
    elif evidence == "signing-input":
        stale = Path(case.values["signing_ca_key_source"])
    elif evidence == "backup":
        stale = Path(case.values[f"{writer.record.backup_order[0]}_backup"])
    else:
        stale = Path(
            case.values[f"{writer.record.publication_order[0]}_destination"]
        )
    foreign = _replace_file(stale)
    next_key = writer.record.publication_order[
        int(writer.record["published_count"])
    ]
    next_destination = Path(case.values[f"{next_key}_destination"])

    with pytest.raises(ApplicationError):
        writer.publish_next()

    assert stale.read_bytes() == foreign
    assert not next_destination.exists()
    pending = _record(case)
    assert pending["checkpoint"] == "publication-pending"
    assert pending["published_count"] == (
        "1" if evidence == "prior-publication" else "0"
    )


@pytest.mark.parametrize("directory", ("active-authority", "stage-root", "backup-root"))
def test_preflight_reauthenticates_planned_directory_identity(
    tmp_path: Path,
    directory: str,
) -> None:
    case = build_service_recovery_case(tmp_path, published=0)
    writer = ManagedServiceWriter.load(
        case.pki / "state/service/recovery-journal",
        pki_dir=case.pki,
    )
    target = {
        "active-authority": case.pki / "authorities/roots/g1",
        "stage-root": Path(case.values["stage_dir"]),
        "backup-root": Path(case.values["backup_dir"]),
    }[directory]
    displaced = target.with_name(f"{target.name}-displaced")
    os.replace(target, displaced)
    shutil.copytree(displaced, target)
    key = writer.record.publication_order[0]

    with pytest.raises(ApplicationError, match="identity changed"):
        writer.publish_next()

    assert target.is_dir()
    assert displaced.is_dir()
    assert not Path(case.values[f"{key}_destination"]).exists()
    assert _record(case)["published_count"] == "0"


def test_directory_mutation_before_evidence_is_preserved_and_rejected(
    tmp_path: Path,
    process_starter: Callable[..., ManagedProcess],
) -> None:
    case = build_service_recovery_case(
        tmp_path,
        key_action=ServiceKeyAction.ROTATE,
        existing_archive_root=False,
        published=14,
    )
    record = _record(case)
    key = record.publication_order[14]
    assert key == "archive_root"
    destination = Path(case.values[f"{key}_destination"])
    process, release = _start_paused(
        process_starter,
        case,
        tmp_path,
        f"publish-{key}-after-publication",
    )
    foreign = destination / "foreign"
    foreign.write_bytes(b"foreign archive state\n")
    foreign.chmod(0o600)
    release.write_bytes(b"")

    result = process.wait()
    assert result.status == 1, result
    assert foreign.read_bytes() == b"foreign archive state\n"
    pending = _record(case)
    assert pending["checkpoint"] == "publication-pending"
    assert pending["published_count"] == "14"
    assert not Path(case.values["archive_dir_destination"]).exists()
    with pytest.raises(ApplicationError):
        recover_service_transaction(case.pki, transaction=case.transaction)
    assert foreign.is_file()
    assert (case.pki / "state/service/recovery-journal").is_file()


def test_directory_stage_replacement_before_descriptor_open_is_preserved(
    tmp_path: Path,
    process_starter: Callable[..., ManagedProcess],
) -> None:
    case = build_service_recovery_case(
        tmp_path,
        existing_service_directories=(),
        published=0,
    )
    record = _record(case)
    key = record.publication_order[0]
    assert key == "service_root"
    stage = Path(case.values["stage_dir"]) / key
    destination = Path(case.values[f"{key}_destination"])
    process, release = _start_paused(
        process_starter,
        case,
        tmp_path,
        f"publish-{key}-after-directory-stage-create",
    )
    displaced = tmp_path / "original-directory-stage"
    os.replace(stage, displaced)
    stage.mkdir(mode=0o700)
    release.write_bytes(b"")

    result = process.wait()
    assert result.status == 1, result
    assert stage.is_dir()
    assert displaced.is_dir()
    assert not destination.exists()
    pending = _record(case)
    assert pending[f"{key}_post_identity"] == "none"
    assert pending["published_count"] == "0"
    with pytest.raises(ApplicationError):
        recover_service_transaction(case.pki, transaction=case.transaction)
    assert stage.is_dir()
    assert displaced.is_dir()


def test_directory_publication_no_clobber_race_preserves_both_objects(
    tmp_path: Path,
    process_starter: Callable[..., ManagedProcess],
) -> None:
    case = build_service_recovery_case(
        tmp_path,
        existing_service_directories=(),
        published=0,
    )
    record = _record(case)
    key = record.publication_order[0]
    stage = Path(case.values["stage_dir"]) / key
    destination = Path(case.values[f"{key}_destination"])
    process, release = _start_paused(
        process_starter,
        case,
        tmp_path,
        f"publish-{key}-before-directory-publication",
    )
    destination.mkdir(mode=0o700)
    release.write_bytes(b"")

    result = process.wait()
    assert result.status == 1, result
    assert stage.is_dir()
    assert destination.is_dir()
    pending = _record(case)
    assert pending[f"{key}_post_identity"] != "none"
    assert pending["published_count"] == "0"
    with pytest.raises(ApplicationError):
        recover_service_transaction(case.pki, transaction=case.transaction)
    assert stage.is_dir()
    assert destination.is_dir()


def test_directory_destination_replacement_after_atomic_publication_is_preserved(
    tmp_path: Path,
    process_starter: Callable[..., ManagedProcess],
) -> None:
    case = build_service_recovery_case(
        tmp_path,
        existing_service_directories=(),
        published=0,
    )
    record = _record(case)
    key = record.publication_order[0]
    stage = Path(case.values["stage_dir"]) / key
    destination = Path(case.values[f"{key}_destination"])
    process, release = _start_paused(
        process_starter,
        case,
        tmp_path,
        f"publish-{key}-after-directory-publication",
    )
    displaced = tmp_path / "published-service-root"
    os.replace(destination, displaced)
    destination.mkdir(mode=0o700)
    release.write_bytes(b"")

    result = process.wait()
    assert result.status == 1, result
    assert not stage.exists()
    assert destination.is_dir()
    assert displaced.is_dir()
    pending = _record(case)
    assert pending[f"{key}_post_identity"] != "none"
    assert pending["published_count"] == "0"
    with pytest.raises(ApplicationError):
        recover_service_transaction(case.pki, transaction=case.transaction)
    assert destination.is_dir()
    assert displaced.is_dir()


@pytest.mark.parametrize(
    "window",
    ("before-publication-evidence", "evidence-before-journal-rewrite"),
)
def test_directory_replacement_between_writer_validation_and_evidence_is_preserved(
    tmp_path: Path,
    process_starter: Callable[..., ManagedProcess],
    window: str,
) -> None:
    case = build_service_recovery_case(
        tmp_path,
        existing_service_directories=(),
        published=0,
    )
    record = _record(case)
    key = record.publication_order[0]
    destination = Path(case.values[f"{key}_destination"])
    later = Path(case.values[f"{record.publication_order[1]}_destination"])
    process, release = _start_paused(
        process_starter,
        case,
        tmp_path,
        f"publish-{key}-{window}",
    )
    displaced = tmp_path / "validated-service-root"
    os.replace(destination, displaced)
    destination.mkdir(mode=0o700)
    replacement_inode = destination.stat().st_ino
    release.write_bytes(b"")

    result = process.wait()
    assert result.status == 1, result
    assert destination.stat().st_ino == replacement_inode
    assert displaced.is_dir()
    assert not later.exists()
    pending = _record(case)
    pending_mutation = next(item for item in pending.mutations if item.key == key)
    expected = pending_mutation.post_identity
    assert isinstance(expected, DirectoryIdentity)
    assert expected.ino == displaced.stat().st_ino
    assert pending["published_count"] == "0"
    with pytest.raises(ApplicationError):
        recover_service_transaction(case.pki, transaction=case.transaction)
    assert destination.stat().st_ino == replacement_inode
    assert displaced.is_dir()
    assert not later.exists()
    assert (case.pki / "state/service/recovery-journal").is_file()


@pytest.mark.parametrize(
    "window",
    ("before-publication-evidence", "evidence-before-journal-rewrite"),
)
def test_file_replacement_between_writer_validation_and_evidence_is_preserved(
    tmp_path: Path,
    process_starter: Callable[..., ManagedProcess],
    window: str,
) -> None:
    case = build_service_recovery_case(tmp_path, published=0)
    record = _record(case)
    key = record.publication_order[0]
    destination = Path(case.values[f"{key}_destination"])
    later = Path(case.values[f"{record.publication_order[1]}_destination"])
    assert not later.exists()
    process, release = _start_paused(
        process_starter,
        case,
        tmp_path,
        f"publish-{key}-{window}",
    )
    replacement = tmp_path / "replacement-service-config"
    shutil.copy2(destination, replacement)
    displaced = tmp_path / "validated-service-config"
    os.replace(destination, displaced)
    os.replace(replacement, destination)
    replacement_inode = destination.stat().st_ino
    release.write_bytes(b"")

    result = process.wait()
    assert result.status == 1, result
    assert destination.stat().st_ino == replacement_inode
    assert displaced.is_file()
    assert not later.exists()
    pending = _record(case)
    mutation = next(item for item in pending.mutations if item.key == key)
    assert isinstance(mutation.stage_identity, FileIdentity)
    assert mutation.stage_identity.ino == displaced.stat().st_ino
    assert pending[f"{key}_post_identity"] == "none"
    assert pending["published_count"] == "0"
    with pytest.raises(ApplicationError):
        recover_service_transaction(case.pki, transaction=case.transaction)
    assert destination.stat().st_ino == replacement_inode
    assert displaced.is_file()
    assert not later.exists()
    assert (case.pki / "state/service/recovery-journal").is_file()


@pytest.mark.parametrize(
    ("boundary", "published"),
    (
        ("before-directory-publication", False),
        ("after-directory-publication", True),
        ("before-publication-evidence", True),
        ("evidence-before-journal-rewrite", True),
    ),
)
def test_directory_publication_stage_and_post_windows_recover_exact_identity(
    tmp_path: Path,
    boundary: str,
    published: bool,
) -> None:
    case = build_service_recovery_case(
        tmp_path,
        existing_service_directories=(),
        published=0,
    )
    writer = _replace_case_journal(case)
    key = writer.record.publication_order[0]
    stage = Path(writer.values["stage_dir"]) / key
    destination = Path(writer.values[f"{key}_destination"])
    writer.fault = FaultHook(failure_at=f"publish-{key}-{boundary}")

    with pytest.raises(ApplicationError):
        writer.publish_next()

    pending = _record(case)
    assert pending[f"{key}_post_identity"] != "none"
    assert stage.exists() != published
    assert destination.exists() == published
    assert recover_service_transaction(
        writer.pki_dir,
        transaction=pending["transaction"],
    ) == 0
    assert not stage.exists()
    assert not destination.exists()
    assert not Path(writer.path).exists()


def test_directory_stage_fault_before_identity_evidence_cleans_only_exact_stage(
    tmp_path: Path,
) -> None:
    case = build_service_recovery_case(
        tmp_path,
        existing_service_directories=(),
        published=0,
    )
    writer = _replace_case_journal(case)
    key = writer.record.publication_order[0]
    stage = Path(writer.values["stage_dir"]) / key
    writer.fault = FaultHook(
        failure_at=f"publish-{key}-after-directory-stage-create"
    )

    with pytest.raises(InjectedFaultError):
        writer.publish_next()

    assert not stage.exists()
    pending = _record(case)
    assert pending[f"{key}_post_identity"] == "none"
    assert recover_service_transaction(
        writer.pki_dir,
        transaction=pending["transaction"],
    ) == 0


@pytest.mark.parametrize(
    ("boundary", "published"),
    (
        ("before-directory-publication", False),
        ("after-directory-publication", True),
    ),
)
def test_directory_publication_hard_crash_recovers_exact_stage_or_destination(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    boundary: str,
    published: bool,
) -> None:
    case = build_service_recovery_case(
        tmp_path,
        existing_service_directories=(),
        published=0,
    )
    record = _record(case)
    key = record.publication_order[0]
    stage = Path(case.values["stage_dir"]) / key
    destination = Path(case.values[f"{key}_destination"])

    crashed = _run_with_crash(
        process_runner,
        case,
        f"publish-{key}-{boundary}",
    )

    assert crashed.status == 128 + signal.SIGKILL, crashed
    pending = _record(case)
    assert pending[f"{key}_post_identity"] != "none"
    assert stage.exists() != published
    assert destination.exists() == published
    assert recover_service_transaction(
        case.pki,
        transaction=pending["transaction"],
    ) == 0
    assert not stage.exists()
    assert not destination.exists()


@pytest.mark.parametrize("boundary", ("before-publication", "after-publication"))
def test_actual_sigterm_stops_at_publication_boundary_with_recoverable_journal(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    boundary: str,
) -> None:
    case = build_service_recovery_case(tmp_path, published=0)
    record = _record(case)
    key = record.publication_order[0]
    destination = Path(case.values[f"{key}_destination"])
    later = Path(case.values[f"{record.publication_order[1]}_destination"])

    result = _run_with_signal(
        process_runner,
        case,
        f"publish-{key}-{boundary}",
    )

    assert result.status == 128 + signal.SIGTERM, result
    interrupted = _record(case)
    assert interrupted["published_count"] == (
        "0" if boundary == "before-publication" else "1"
    )
    assert destination.exists() == (boundary == "after-publication")
    assert not later.exists()
    assert recover_service_transaction(case.pki, transaction=case.transaction) == 0
    assert not destination.exists()
