import os
import re
import stat
from collections.abc import Callable, Mapping
from hashlib import sha256
from pathlib import Path

import pytest

from ..harness import ProcessResult
from .conftest import RolloverTools, RolloverWorkspace


pytestmark = pytest.mark.pki

VALID_TRUST_CONSUMERS = """consumers:
  managed-cluster:
    kind: managed
  firewall.manual:
    kind: manual
"""

INTERMEDIATE_EARLY_CHECKPOINTS = (
    "transaction-dir-pending",
    "transaction-dir-done",
    "long-stage-pending",
    "long-stage-done",
    "backup-session-pending",
    "backup-session-done",
    "reserve-intermediate-pending",
    "reserve-intermediate-done",
    "stage-dir-pending",
    "stage-dir-done",
    "sensitive-stage-pending",
    "sensitive-root-stage-pending",
    "sensitive-root-stage-done",
    "sensitive-root-private-pending",
    "sensitive-root-private-done",
    "sensitive-intermediate-stage-pending",
    "sensitive-intermediate-stage-done",
    "sensitive-intermediate-private-pending",
    "sensitive-intermediate-private-done",
    "copied-root-key-pending",
    "copied-root-key-done",
    "sensitive-stage-done",
    "intermediate-stage-config-pending",
    "intermediate-stage-config-done",
    "intermediate-key-pending",
    "intermediate-key-done",
    "intermediate-csr-pending",
    "intermediate-csr-done",
    "intermediate-signing-pending",
    "intermediate-signing-done",
    "chain-pending",
    "chain-done",
    "evidence-stage-pending",
    "evidence-stage-done",
)

ROOT_CRYPTO_CHECKPOINTS = (
    "candidate-root-stage-pending",
    "candidate-root-directory-pending",
    "candidate-root-directory-done",
    "candidate-root-private-pending",
    "candidate-root-private-done",
    "candidate-intermediate-directory-pending",
    "candidate-intermediate-directory-done",
    "candidate-intermediate-private-pending",
    "candidate-intermediate-private-done",
    "candidate-root-stage-done",
    "root-key-pending",
    "root-key-done",
    "root-certificate-pending",
    "root-certificate-done",
)

INTERMEDIATE_HOSTILE_DIRECTORIES = (
    ("sensitive-stage-pending", "stage/root"),
    ("sensitive-stage-done", "stage/root"),
    ("sensitive-root-stage-pending", "stage/root"),
    ("sensitive-root-stage-done", "stage/root"),
    ("sensitive-root-private-pending", "stage/root/private"),
    ("sensitive-root-private-done", "stage/root/private"),
    ("sensitive-intermediate-stage-pending", "stage/intermediate"),
    ("sensitive-intermediate-stage-done", "stage/intermediate"),
    (
        "sensitive-intermediate-private-pending",
        "stage/intermediate/private",
    ),
    ("sensitive-intermediate-private-done", "stage/intermediate/private"),
)

INTERMEDIATE_HOSTILE_FILES = (
    ("copied-root-key-pending", "stage/root/private/root-ca.key"),
    ("copied-root-key-done", "stage/root/private/root-ca.key"),
    (
        "intermediate-key-pending",
        "stage/intermediate/private/intermediate-ca.key",
    ),
    (
        "intermediate-key-done",
        "stage/intermediate/private/intermediate-ca.key",
    ),
    (
        "intermediate-signing-pending",
        "stage/intermediate/certs/intermediate-ca.crt",
    ),
    (
        "intermediate-signing-done",
        "stage/intermediate/certs/intermediate-ca.crt",
    ),
)

ROOT_HOSTILE_DIRECTORIES = (
    ("candidate-root-stage-pending", "stage/root"),
    ("candidate-root-stage-done", "stage/root"),
    ("candidate-root-directory-pending", "stage/root"),
    ("candidate-root-directory-done", "stage/root"),
    ("candidate-root-private-pending", "stage/root/private"),
    ("candidate-root-private-done", "stage/root/private"),
    ("candidate-intermediate-directory-pending", "stage/intermediate"),
    ("candidate-intermediate-directory-done", "stage/intermediate"),
    ("candidate-intermediate-private-pending", "stage/intermediate/private"),
    ("candidate-intermediate-private-done", "stage/intermediate/private"),
)

ROOT_HOSTILE_FILES = (
    ("root-key-pending", "stage/root/private/root-ca.key"),
    ("root-key-done", "stage/root/private/root-ca.key"),
    (
        "intermediate-key-pending",
        "stage/intermediate/private/intermediate-ca.key",
    ),
    (
        "intermediate-key-done",
        "stage/intermediate/private/intermediate-ca.key",
    ),
    (
        "intermediate-signing-pending",
        "stage/intermediate/certs/intermediate-ca.crt",
    ),
    (
        "intermediate-signing-done",
        "stage/intermediate/certs/intermediate-ca.crt",
    ),
)

INTERMEDIATE_STAGED_REWRITES = (
    ("copied-root-key-done", "stage/root/private/root-ca.key"),
    (
        "intermediate-key-done",
        "stage/intermediate/private/intermediate-ca.key",
    ),
    (
        "intermediate-csr-done",
        "stage/intermediate/csr/intermediate-ca.csr",
    ),
    (
        "intermediate-signing-done",
        "stage/intermediate/certs/intermediate-ca.crt",
    ),
    ("chain-done", "stage/intermediate/certs/ca-chain.crt"),
)

ROOT_STAGED_REWRITES = (
    ("root-key-done", "stage/root/private/root-ca.key"),
    ("root-certificate-done", "stage/root/certs/root-ca.crt"),
)

ROOT_DB_RELATIVES = {
    "index": "index.txt",
    "index_attr": "index.txt.attr",
    "serial": "serial",
    "crlnumber": "crlnumber",
    "index_old": "index.txt.old",
    "index_attr_old": "index.txt.attr.old",
    "serial_old": "serial.old",
    "crlnumber_old": "crlnumber.old",
    "newcert": "newcerts/{issued_serial}.pem",
}
PRESENT_ROOT_DB_KEYS = (
    "index",
    "index_attr",
    "serial",
    "crlnumber",
    "index_old",
    "index_attr_old",
    "serial_old",
    "newcert",
)
INTERMEDIATE_MAJOR_ROLLBACK_BOUNDARIES = (
    "after-journal",
    "after-root-db",
    "after-state",
)
INTERMEDIATE_MAJOR_RESUME_BOUNDARIES = (
    "after-intermediate-candidate",
    "after-consumed",
    "cleanup-root-stage-removed",
    "after-pointer",
)
INTERMEDIATE_MAJOR_DURABLE_STEPS = {
    "after-journal": "none",
    "after-root-db": "publish-root-db-newcert-done",
    "after-state": "publish-state-done",
    "after-intermediate-candidate": "publish-intermediate-done",
    "after-consumed": "consume-intermediate-done",
    "cleanup-root-stage-removed": "cleanup-root-stage-pending",
    "after-pointer": "publish-pointer-done",
}

_JOURNAL_FIELDS = {
    "schema",
    "operation",
    "transaction",
    "type",
    "phase",
    "committed",
    "recovery_step",
    "candidate_root",
    "candidate_intermediate",
}
_JOURNAL_KEY = re.compile(r"[a-z][a-z0-9_]*")
_TRANSACTION = re.compile(
    r"prepare-(?:root|intermediate)-[0-9]{8}-[0-9]{6}-[0-9]+"
)


def _metadata(path: Path) -> tuple[int, int, int, int, int]:
    value = path.stat()
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
    )


def _read_strict_public_file(
    path: Path,
) -> tuple[bytes, tuple[int, int, int, int, int, int, int, int]]:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        assert stat.S_ISREG(metadata.st_mode)
        assert stat.S_IMODE(metadata.st_mode) == 0o600
        assert metadata.st_uid == os.getuid()
        assert metadata.st_nlink == 1
        assert metadata.st_size <= 256 * 1024

        chunks = []
        remaining = 256 * 1024 + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        assert len(content) <= 256 * 1024
        snapshot = (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
            metadata.st_uid,
            metadata.st_nlink,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        )
    finally:
        os.close(descriptor)
    return content, snapshot


def _next_generation(workspace: RolloverWorkspace, rollover_type: str) -> int:
    if rollover_type == "root":
        pattern = re.compile(r"g([1-9][0-9]*)")
        directories = (workspace.pki / "authorities/roots",)
    else:
        pattern = re.compile(r"g1-i([1-9][0-9]*)")
        directories = (workspace.pki / "authorities/intermediates",)
    directories += (workspace.pki / "state/generation-reservations",)

    maximum = 1
    for directory in directories:
        for path in directory.iterdir():
            match = pattern.fullmatch(path.name)
            if match:
                maximum = max(maximum, int(match.group(1)))
    return maximum + 1


def _read_strict_record(path: Path) -> dict[str, str]:
    content, _ = _read_strict_public_file(path)

    text = content.decode("ascii")
    assert text.endswith("\n")
    record = {}
    seen = set()
    for line in text.splitlines():
        key, separator, value = line.partition("=")
        assert separator and _JOURNAL_KEY.fullmatch(key)
        assert key not in seen
        assert value and not any(ord(character) < 32 for character in value)
        seen.add(key)
        record[key] = value
    return record


def _read_public_journal(
    path: Path, expected_committed: str = "false"
) -> dict[str, str]:
    record = _read_strict_record(path)
    selected = {key: record[key] for key in _JOURNAL_FIELDS}

    assert selected.keys() == _JOURNAL_FIELDS
    assert selected["schema"] == "5"
    assert selected["operation"] == "rollover-prepare"
    assert selected["committed"] == expected_committed
    assert _TRANSACTION.fullmatch(selected["transaction"])
    return selected


def _prepare_command(
    tools: RolloverTools,
    workspace: RolloverWorkspace,
    receipt: Path,
    rollover_type: str,
    generation: int,
) -> list[str | Path]:
    command: list[str | Path] = [
        *tools.rollover,
        "prepare",
        "--namespace",
        workspace.namespace,
        "--type",
        rollover_type,
        "--backup-receipt",
        receipt,
    ]
    if rollover_type == "root":
        command.extend(
            (
                "--root-name",
                f"Test G{generation} Root CA",
                "--intermediate-name",
                f"Test G{generation}-I1 Intermediate CA",
            )
        )
    else:
        command.extend(
            (
                "--intermediate-name",
                f"Test G1-I{generation} Intermediate CA",
            )
        )
    command.extend(
        (
            "--org",
            "Test",
            "--country",
            "US",
            "--root-pass-file",
            workspace.passphrase_file,
            "--intermediate-pass-file",
            workspace.passphrase_file,
        )
    )
    if rollover_type == "root":
        command.extend(("--private-repo", workspace.private_repo))
    return command


def _crash_prepare(
    tools: RolloverTools,
    workspace: RolloverWorkspace,
    receipt: Path,
    rollover_type: str,
    generation: int,
    checkpoint: str,
    environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
    expected_recovery_step: str | None = None,
) -> dict[str, str]:
    crash_environment = dict(environment)
    crash_environment["PLATFORM_PKI_PREPARE_CRASH_AT"] = checkpoint
    result = process_runner(
        _prepare_command(
            tools, workspace, receipt, rollover_type, generation
        ),
        env=crash_environment,
        timeout=120,
    )
    assert result.status == 137, result
    journal_path = workspace.pki / "state/rollover/journal"
    journal = _read_public_journal(journal_path)
    full_journal = _read_strict_record(journal_path)
    assert journal["type"] == rollover_type
    assert journal["recovery_step"] == (expected_recovery_step or checkpoint)
    expected_manifests = {
        Path(full_journal[field])
        for field in (
            "transaction_tree_manifest",
            "transaction_tree_manifest_pending",
        )
        if full_journal[field] != "none"
    }
    actual_manifests = set(
        (workspace.pki / "state/rollover").glob(
            f".{journal['transaction']}.transaction-tree.*"
        )
    )
    assert actual_manifests == expected_manifests
    return journal


def _recover(
    tools: RolloverTools,
    workspace: RolloverWorkspace,
    transaction: str,
    action: str,
    environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> ProcessResult:
    return process_runner(
        [
            *tools.rollover,
            "recover",
            "--namespace",
            workspace.namespace,
            "--transaction",
            transaction,
            "--action",
            action,
            "--yes",
        ],
        env=environment,
        timeout=120,
    )


def _rollback(
    tools: RolloverTools,
    workspace: RolloverWorkspace,
    transaction: str,
    environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> ProcessResult:
    return _recover(
        tools,
        workspace,
        transaction,
        "rollback",
        environment,
        process_runner,
    )


def _rewrite_same_inode_same_second(path: Path) -> tuple[os.stat_result, os.stat_result]:
    descriptor = os.open(path, os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        assert stat.S_ISREG(before.st_mode)
        assert before.st_size > 0
        os.pwrite(descriptor, b"\0", 0)
        fraction = (before.st_mtime_ns % 1_000_000_000 + 100_000_000) % 1_000_000_000
        timestamp = before.st_mtime_ns // 1_000_000_000 * 1_000_000_000 + fraction
        os.utime(descriptor, ns=(timestamp, timestamp))
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)

    assert before.st_dev == after.st_dev
    assert before.st_ino == after.st_ino
    assert before.st_mode == after.st_mode
    assert before.st_size == after.st_size
    assert before.st_mtime_ns != after.st_mtime_ns
    assert before.st_mtime_ns // 1_000_000_000 == (
        after.st_mtime_ns // 1_000_000_000
    )
    return before, after


def _root_db_path(transaction_directory: Path, record: dict[str, str], key: str) -> Path:
    relative = ROOT_DB_RELATIVES[key].format(issued_serial=record["issued_serial"])
    return transaction_directory / "stage/root" / relative


def _assert_failed_control_state(
    workspace: RolloverWorkspace,
    journal: dict[str, str],
    *,
    expected_committed: str = "false",
    expected_phase: str | None = None,
    expected_recovery_step: str | None = None,
    expected_marker: bool = True,
) -> None:
    journal_after = _read_public_journal(
        workspace.pki / "state/rollover/journal", expected_committed
    )
    assert journal_after["transaction"] == journal["transaction"]
    assert journal_after["type"] == journal["type"]
    assert journal_after["candidate_root"] == journal["candidate_root"]
    assert journal_after["candidate_intermediate"] == journal["candidate_intermediate"]
    if expected_phase is not None:
        assert journal_after["phase"] == expected_phase
    if expected_recovery_step is not None:
        assert journal_after["recovery_step"] == expected_recovery_step
    marker_path = workspace.pki / "state/rollover/recovery-required"
    if not expected_marker:
        assert not marker_path.exists() and not marker_path.is_symlink()
        return
    marker = _read_strict_record(marker_path)
    assert marker["transaction"] == journal["transaction"]
    assert marker["operation"] == "rollover-prepare"
    if expected_committed == "true":
        assert marker["terminal_outcome"] == "rolled-back"


def _assert_rolled_back(
    workspace: RolloverWorkspace,
    transaction: str,
    candidate_root: str,
    candidate_intermediate: str,
) -> None:
    assert not (workspace.pki / "state/rollover/journal").exists()
    assert not (workspace.pki / "state/rollover/recovery-required").exists()
    assert not (workspace.pki / "state/rollover" / transaction).exists()
    assert not (workspace.pki / "state/active-rollover").exists()
    assert not (
        workspace.pki / "authorities/intermediates" / candidate_intermediate
    ).exists()
    if candidate_root != "g1":
        assert not (workspace.pki / "authorities/roots" / candidate_root).exists()
    assert not tuple(
        (workspace.pki / "state/rollover").glob(
            f".{transaction}.transaction-tree.*"
        )
    )


def test_intermediate_early_checkpoint_rollback(
    rollover_tools: RolloverTools,
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> None:
    assert len(INTERMEDIATE_EARLY_CHECKPOINTS) == 34
    workspace = rollover_case_factory("intermediate-early-checkpoint-rollback")
    receipt = backup_receipt_factory(workspace)
    active_issuer = workspace.pki / "state/active-issuer"
    active_before = active_issuer.read_text()
    active_metadata = _metadata(active_issuer)

    generations = []
    for checkpoint in INTERMEDIATE_EARLY_CHECKPOINTS:
        generation = _next_generation(workspace, "intermediate")
        generations.append(generation)
        journal = _crash_prepare(
            rollover_tools,
            workspace,
            receipt,
            "intermediate",
            generation,
            checkpoint,
            isolated_environment,
            process_runner,
        )
        assert journal["candidate_root"] == "g1"
        assert journal["candidate_intermediate"] == f"g1-i{generation}"

        result = _rollback(
            rollover_tools,
            workspace,
            journal["transaction"],
            isolated_environment,
            process_runner,
        )

        assert result.status == 0, result
        assert result.stderr == ""
        _assert_rolled_back(
            workspace,
            journal["transaction"],
            "g1",
            f"g1-i{generation}",
        )
        assert active_issuer.read_text() == active_before
        assert _metadata(active_issuer) == active_metadata

    assert generations[:5] == [2] * 5
    assert generations[5:] == list(range(3, 32))


def test_root_crypto_checkpoint_rollback(
    rollover_tools: RolloverTools,
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    private_text_writer: Callable[[Path, str], None],
    process_runner: Callable[..., ProcessResult],
) -> None:
    assert len(ROOT_CRYPTO_CHECKPOINTS) == 14
    workspace = rollover_case_factory("root-crypto-checkpoint-rollback")
    private_text_writer(
        workspace.private_repo / "pki/trust-consumers.yml",
        VALID_TRUST_CONSUMERS,
    )
    receipt = backup_receipt_factory(workspace)
    active_issuer = workspace.pki / "state/active-issuer"
    active_before = active_issuer.read_text()
    active_metadata = _metadata(active_issuer)

    generations = []
    for checkpoint in ROOT_CRYPTO_CHECKPOINTS:
        generation = _next_generation(workspace, "root")
        generations.append(generation)
        journal = _crash_prepare(
            rollover_tools,
            workspace,
            receipt,
            "root",
            generation,
            checkpoint,
            isolated_environment,
            process_runner,
        )
        assert journal["candidate_root"] == f"g{generation}"
        assert journal["candidate_intermediate"] == f"g{generation}-i1"

        result = _rollback(
            rollover_tools,
            workspace,
            journal["transaction"],
            isolated_environment,
            process_runner,
        )

        assert result.status == 0, result
        assert result.stderr == ""
        _assert_rolled_back(
            workspace,
            journal["transaction"],
            f"g{generation}",
            f"g{generation}-i1",
        )
        assert active_issuer.read_text() == active_before
        assert _metadata(active_issuer) == active_metadata


    assert generations == list(range(2, 16))


@pytest.mark.parametrize(
    ("checkpoint", "relative"),
    tuple(
        pytest.param(checkpoint, relative, id=checkpoint)
        for checkpoint, relative in INTERMEDIATE_HOSTILE_DIRECTORIES
    ),
)
def test_intermediate_hostile_staged_directory(
    rollover_tools: RolloverTools,
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
    checkpoint: str,
    relative: str,
) -> None:
    assert len(INTERMEDIATE_HOSTILE_DIRECTORIES) == 10
    workspace = rollover_case_factory(
        f"intermediate-hostile-staged-directory-{checkpoint}"
    )
    receipt = backup_receipt_factory(workspace)
    active_issuer = workspace.pki / "state/active-issuer"
    active_before = active_issuer.read_text()
    active_metadata = _metadata(active_issuer)
    journal = _crash_prepare(
        rollover_tools,
        workspace,
        receipt,
        "intermediate",
        2,
        checkpoint,
        isolated_environment,
        process_runner,
    )

    transaction_directory = (
        workspace.pki / "state/rollover" / journal["transaction"]
    )
    hostile = transaction_directory / relative
    hostile.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if hostile.exists() or hostile.is_symlink():
        hostile.rename(workspace.root / f"original-{checkpoint}")
    hostile.mkdir(mode=0o700)
    sentinel = hostile / "sentinel"
    sentinel.write_text("hostile\n")
    sentinel.chmod(0o600)
    journal_path = workspace.pki / "state/rollover/journal"
    marker = workspace.pki / "state/rollover/recovery-required"
    transaction_metadata = _metadata(transaction_directory)
    hostile_metadata = _metadata(hostile)
    sentinel_before = _read_strict_public_file(sentinel)

    result = _rollback(
        rollover_tools,
        workspace,
        journal["transaction"],
        isolated_environment,
        process_runner,
    )

    assert result.status == 1, result
    assert result.stdout == ""
    assert result.stderr == (
        "[ERROR] Cannot remove preparation transaction staging\n"
    )
    journal_after = _read_public_journal(journal_path, "true")
    assert journal_after["transaction"] == journal["transaction"]
    assert journal_after["type"] == journal["type"]
    assert journal_after["candidate_root"] == journal["candidate_root"]
    assert journal_after["candidate_intermediate"] == journal["candidate_intermediate"]
    assert journal_after["phase"] == "terminal-cleanup"
    assert journal_after["recovery_step"] == "terminal-transaction-pending"
    marker_content, _ = _read_strict_public_file(marker)
    assert marker_content.decode("ascii") == (
        f"transaction={journal['transaction']}\n"
        "operation=rollover-prepare\n"
        "terminal_outcome=rolled-back\n"
    )
    assert transaction_directory.is_dir()
    assert not transaction_directory.is_symlink()
    assert _metadata(transaction_directory)[:3] == transaction_metadata[:3]
    assert hostile.is_dir()
    assert not hostile.is_symlink()
    assert _metadata(hostile) == hostile_metadata
    assert _read_strict_public_file(sentinel) == sentinel_before
    assert active_issuer.read_text() == active_before
    assert _metadata(active_issuer) == active_metadata


def _hostile_staged_object(
    tools: RolloverTools,
    workspace: RolloverWorkspace,
    receipt: Path,
    rollover_type: str,
    checkpoint: str,
    relative: str,
    object_type: str,
    environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> None:
    active_issuer = workspace.pki / "state/active-issuer"
    active_before = active_issuer.read_text()
    active_metadata = _metadata(active_issuer)
    journal = _crash_prepare(
        tools,
        workspace,
        receipt,
        rollover_type,
        2,
        checkpoint,
        environment,
        process_runner,
    )
    transaction_directory = workspace.pki / "state/rollover" / journal["transaction"]
    hostile = transaction_directory / relative
    hostile.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if hostile.exists() or hostile.is_symlink():
        hostile.rename(workspace.root / f"original-{checkpoint}")

    if object_type == "directory":
        hostile.mkdir(mode=0o700)
        sentinel = hostile / "sentinel"
        sentinel.write_text("hostile\n")
        sentinel.chmod(0o600)
        hostile_before = _metadata(hostile)
        content_before = _read_strict_public_file(sentinel)
    else:
        hostile.write_text(f"hostile-{checkpoint}\n")
        hostile.chmod(0o600)
        hostile_before = _read_strict_public_file(hostile)
        content_before = None

    result = _rollback(
        tools,
        workspace,
        journal["transaction"],
        environment,
        process_runner,
    )

    assert result.status == 1, result
    assert result.stdout == ""
    assert result.stderr.startswith("[ERROR] ")
    if object_type == "directory":
        assert hostile.is_dir() and not hostile.is_symlink()
        assert _metadata(hostile) == hostile_before
        assert _read_strict_public_file(hostile / "sentinel") == content_before
        journal_after = _read_public_journal(
            workspace.pki / "state/rollover/journal", "true"
        )
        assert journal_after["phase"] == "terminal-cleanup"
        assert journal_after["recovery_step"] == "terminal-transaction-pending"
    else:
        assert _read_strict_public_file(hostile) == hostile_before
        _assert_failed_control_state(
            workspace,
            journal,
            expected_committed="true",
            expected_phase="terminal-cleanup",
            expected_recovery_step="terminal-transaction-pending",
        )
    assert active_issuer.read_text() == active_before
    assert _metadata(active_issuer) == active_metadata


@pytest.mark.parametrize(
    ("checkpoint", "relative"),
    tuple(
        pytest.param(checkpoint, relative, id=checkpoint)
        for checkpoint, relative in INTERMEDIATE_HOSTILE_FILES
    ),
)
def test_intermediate_hostile_staged_file(
    rollover_tools: RolloverTools,
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
    checkpoint: str,
    relative: str,
) -> None:
    assert len(INTERMEDIATE_HOSTILE_FILES) == 6
    workspace = rollover_case_factory(f"intermediate-hostile-file-{checkpoint}")
    receipt = backup_receipt_factory(workspace)
    _hostile_staged_object(
        rollover_tools,
        workspace,
        receipt,
        "intermediate",
        checkpoint,
        relative,
        "file",
        isolated_environment,
        process_runner,
    )


@pytest.mark.parametrize(
    ("checkpoint", "relative"),
    tuple(
        pytest.param(checkpoint, relative, id=checkpoint)
        for checkpoint, relative in ROOT_HOSTILE_DIRECTORIES
    ),
)
def test_root_hostile_staged_directory(
    rollover_tools: RolloverTools,
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    private_text_writer: Callable[[Path, str], None],
    process_runner: Callable[..., ProcessResult],
    checkpoint: str,
    relative: str,
) -> None:
    assert len(ROOT_HOSTILE_DIRECTORIES) == 10
    workspace = rollover_case_factory(f"root-hostile-directory-{checkpoint}")
    private_text_writer(
        workspace.private_repo / "pki/trust-consumers.yml",
        VALID_TRUST_CONSUMERS,
    )
    receipt = backup_receipt_factory(workspace)
    _hostile_staged_object(
        rollover_tools,
        workspace,
        receipt,
        "root",
        checkpoint,
        relative,
        "directory",
        isolated_environment,
        process_runner,
    )


@pytest.mark.parametrize(
    ("checkpoint", "relative"),
    tuple(
        pytest.param(checkpoint, relative, id=checkpoint)
        for checkpoint, relative in ROOT_HOSTILE_FILES
    ),
)
def test_root_hostile_staged_file(
    rollover_tools: RolloverTools,
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    private_text_writer: Callable[[Path, str], None],
    process_runner: Callable[..., ProcessResult],
    checkpoint: str,
    relative: str,
) -> None:
    assert len(ROOT_HOSTILE_FILES) == 6
    workspace = rollover_case_factory(f"root-hostile-file-{checkpoint}")
    private_text_writer(
        workspace.private_repo / "pki/trust-consumers.yml",
        VALID_TRUST_CONSUMERS,
    )
    receipt = backup_receipt_factory(workspace)
    _hostile_staged_object(
        rollover_tools,
        workspace,
        receipt,
        "root",
        checkpoint,
        relative,
        "file",
        isolated_environment,
        process_runner,
    )


def _same_inode_staged_rewrite(
    tools: RolloverTools,
    workspace: RolloverWorkspace,
    receipt: Path,
    rollover_type: str,
    checkpoint: str,
    relative: str,
    environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> None:
    active_issuer = workspace.pki / "state/active-issuer"
    active_before = active_issuer.read_text()
    active_metadata = _metadata(active_issuer)
    journal = _crash_prepare(
        tools,
        workspace,
        receipt,
        rollover_type,
        2,
        checkpoint,
        environment,
        process_runner,
    )
    rewritten = (
        workspace.pki / "state/rollover" / journal["transaction"] / relative
    )
    _, after_rewrite = _rewrite_same_inode_same_second(rewritten)

    result = _rollback(
        tools,
        workspace,
        journal["transaction"],
        environment,
        process_runner,
    )

    after_recovery = rewritten.stat()
    assert result.status == 1, result
    assert result.stdout == ""
    assert result.stderr.startswith("[ERROR] ")
    assert after_recovery.st_dev == after_rewrite.st_dev
    assert after_recovery.st_ino == after_rewrite.st_ino
    assert after_recovery.st_mode == after_rewrite.st_mode
    assert after_recovery.st_size == after_rewrite.st_size
    assert after_recovery.st_mtime_ns == after_rewrite.st_mtime_ns
    _assert_failed_control_state(
        workspace,
        journal,
        expected_committed="true",
        expected_phase="terminal-cleanup",
        expected_recovery_step="terminal-transaction-pending",
    )
    assert active_issuer.read_text() == active_before
    assert _metadata(active_issuer) == active_metadata


@pytest.mark.parametrize(
    ("checkpoint", "relative"),
    tuple(
        pytest.param(checkpoint, relative, id=checkpoint)
        for checkpoint, relative in INTERMEDIATE_STAGED_REWRITES
    ),
)
def test_intermediate_same_inode_staged_rewrite(
    rollover_tools: RolloverTools,
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
    checkpoint: str,
    relative: str,
) -> None:
    assert len(INTERMEDIATE_STAGED_REWRITES) == 5
    workspace = rollover_case_factory(f"intermediate-staged-rewrite-{checkpoint}")
    receipt = backup_receipt_factory(workspace)
    _same_inode_staged_rewrite(
        rollover_tools,
        workspace,
        receipt,
        "intermediate",
        checkpoint,
        relative,
        isolated_environment,
        process_runner,
    )


@pytest.mark.parametrize(
    ("checkpoint", "relative"),
    tuple(
        pytest.param(checkpoint, relative, id=checkpoint)
        for checkpoint, relative in ROOT_STAGED_REWRITES
    ),
)
def test_root_same_inode_staged_rewrite(
    rollover_tools: RolloverTools,
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    private_text_writer: Callable[[Path, str], None],
    process_runner: Callable[..., ProcessResult],
    checkpoint: str,
    relative: str,
) -> None:
    assert len(ROOT_STAGED_REWRITES) == 2
    workspace = rollover_case_factory(f"root-staged-rewrite-{checkpoint}")
    private_text_writer(
        workspace.private_repo / "pki/trust-consumers.yml",
        VALID_TRUST_CONSUMERS,
    )
    receipt = backup_receipt_factory(workspace)
    _same_inode_staged_rewrite(
        rollover_tools,
        workspace,
        receipt,
        "root",
        checkpoint,
        relative,
        isolated_environment,
        process_runner,
    )


def _crash_after_staged(
    tools: RolloverTools,
    workspace: RolloverWorkspace,
    receipt: Path,
    environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> tuple[dict[str, str], dict[str, str], Path]:
    selected = _crash_prepare(
        tools,
        workspace,
        receipt,
        "intermediate",
        2,
        "after-staged",
        environment,
        process_runner,
        "evidence-stage-done",
    )
    journal_path = workspace.pki / "state/rollover/journal"
    record = _read_strict_record(journal_path)
    assert record["transaction"] == selected["transaction"]
    transaction_directory = workspace.pki / "state/rollover" / selected["transaction"]
    present = tuple(
        key
        for key in ROOT_DB_RELATIVES
        if record[f"root_{key}_source_identity"] != "absent"
    )
    assert present == PRESENT_ROOT_DB_KEYS
    return selected, record, transaction_directory


def test_staged_root_db_source_identities(
    rollover_tools: RolloverTools,
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> None:
    workspace = rollover_case_factory("staged-root-db-source-identities")
    receipt = backup_receipt_factory(workspace)
    journal, record, transaction_directory = _crash_after_staged(
        rollover_tools,
        workspace,
        receipt,
        isolated_environment,
        process_runner,
    )
    common_library = (
        Path(__file__).resolve().parents[2]
        / "tests/pki/oracles/final-bash-source/lib/platform-pki-common.sh"
    )

    for key in PRESENT_ROOT_DB_KEYS:
        source = _root_db_path(transaction_directory, record, key)
        identity = process_runner(
            [
                "bash",
                "-c",
                'source "$1"; pki_file_identity "$2"',
                "_",
                common_library,
                source,
            ],
            env=isolated_environment,
            timeout=10,
        )
        assert identity.status == 0
        assert identity.stderr == ""
        assert identity.stdout == f"{record[f'root_{key}_source_identity']}\n"

    result = _rollback(
        rollover_tools,
        workspace,
        journal["transaction"],
        isolated_environment,
        process_runner,
    )
    assert result.status == 0
    assert result.stderr == ""
    _assert_rolled_back(workspace, journal["transaction"], "g1", "g1-i2")


@pytest.mark.parametrize("key", PRESENT_ROOT_DB_KEYS)
def test_replaced_staged_root_db_source(
    rollover_tools: RolloverTools,
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
    key: str,
) -> None:
    workspace = rollover_case_factory(f"replaced-staged-root-db-{key}")
    receipt = backup_receipt_factory(workspace)
    journal, record, transaction_directory = _crash_after_staged(
        rollover_tools,
        workspace,
        receipt,
        isolated_environment,
        process_runner,
    )
    active_issuer = workspace.pki / "state/active-issuer"
    active_before = active_issuer.read_text()
    active_metadata = _metadata(active_issuer)
    hostile = _root_db_path(transaction_directory, record, key)
    hostile.rename(workspace.root / f"original-{key}")
    hostile.write_text(f"hostile-{key}\n")
    hostile.chmod(0o600)
    hostile_before = _read_strict_public_file(hostile)

    result = _recover(
        rollover_tools,
        workspace,
        journal["transaction"],
        "resume",
        isolated_environment,
        process_runner,
    )

    assert result.status == 1, result
    assert result.stdout == ""
    assert result.stderr.startswith("[ERROR] Staged root ")
    assert _read_strict_public_file(hostile) == hostile_before
    _assert_failed_control_state(workspace, journal, expected_marker=False)
    assert active_issuer.read_text() == active_before
    assert _metadata(active_issuer) == active_metadata


@pytest.mark.parametrize("key", PRESENT_ROOT_DB_KEYS)
def test_same_inode_root_db_rewrite(
    rollover_tools: RolloverTools,
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
    key: str,
) -> None:
    workspace = rollover_case_factory(f"same-inode-root-db-{key}")
    receipt = backup_receipt_factory(workspace)
    journal, record, transaction_directory = _crash_after_staged(
        rollover_tools,
        workspace,
        receipt,
        isolated_environment,
        process_runner,
    )
    active_issuer = workspace.pki / "state/active-issuer"
    active_before = active_issuer.read_text()
    active_metadata = _metadata(active_issuer)
    rewritten = _root_db_path(transaction_directory, record, key)
    _, after_rewrite = _rewrite_same_inode_same_second(rewritten)

    result = _recover(
        rollover_tools,
        workspace,
        journal["transaction"],
        "resume",
        isolated_environment,
        process_runner,
    )

    after_recovery = rewritten.stat()
    assert result.status == 1, result
    assert result.stdout == ""
    assert result.stderr.startswith("[ERROR] Staged root ")
    assert after_recovery.st_dev == after_rewrite.st_dev
    assert after_recovery.st_ino == after_rewrite.st_ino
    assert after_recovery.st_mode == after_rewrite.st_mode
    assert after_recovery.st_size == after_rewrite.st_size
    assert after_recovery.st_mtime_ns == after_rewrite.st_mtime_ns
    _assert_failed_control_state(workspace, journal, expected_marker=False)
    assert active_issuer.read_text() == active_before
    assert _metadata(active_issuer) == active_metadata


@pytest.mark.parametrize("checkpoint", INTERMEDIATE_MAJOR_ROLLBACK_BOUNDARIES)
def test_intermediate_major_boundary_rollback(
    rollover_tools: RolloverTools,
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
    checkpoint: str,
) -> None:
    assert len(INTERMEDIATE_MAJOR_ROLLBACK_BOUNDARIES) == 3
    workspace = rollover_case_factory(f"intermediate-major-rollback-{checkpoint}")
    receipt = backup_receipt_factory(workspace)
    active_issuer = workspace.pki / "state/active-issuer"
    active_before = active_issuer.read_text()
    active_metadata = _metadata(active_issuer)
    journal = _crash_prepare(
        rollover_tools,
        workspace,
        receipt,
        "intermediate",
        2,
        checkpoint,
        isolated_environment,
        process_runner,
        INTERMEDIATE_MAJOR_DURABLE_STEPS[checkpoint],
    )

    result = _rollback(
        rollover_tools,
        workspace,
        journal["transaction"],
        isolated_environment,
        process_runner,
    )

    assert result.status == 0, result
    assert result.stderr == ""
    if checkpoint == "after-journal":
        expected_stdout = (
            f"[OK] Rolled back planned preparation transaction: "
            f"{journal['transaction']}\n"
        )
    else:
        expected_stdout = (
            f"[OK] Rolled back preparation transaction: {journal['transaction']}\n"
        )
    assert result.stdout == expected_stdout
    _assert_rolled_back(workspace, journal["transaction"], "g1", "g1-i2")
    assert active_issuer.read_text() == active_before
    assert _metadata(active_issuer) == active_metadata


@pytest.mark.parametrize("checkpoint", INTERMEDIATE_MAJOR_RESUME_BOUNDARIES)
def test_intermediate_major_boundary_resume(
    rollover_tools: RolloverTools,
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
    checkpoint: str,
) -> None:
    assert len(INTERMEDIATE_MAJOR_RESUME_BOUNDARIES) == 4
    workspace = rollover_case_factory(f"intermediate-major-resume-{checkpoint}")
    receipt = backup_receipt_factory(workspace)
    active_issuer = workspace.pki / "state/active-issuer"
    active_before = active_issuer.read_text()
    active_metadata = _metadata(active_issuer)
    journal = _crash_prepare(
        rollover_tools,
        workspace,
        receipt,
        "intermediate",
        2,
        checkpoint,
        isolated_environment,
        process_runner,
        INTERMEDIATE_MAJOR_DURABLE_STEPS[checkpoint],
    )

    result = _recover(
        rollover_tools,
        workspace,
        journal["transaction"],
        "resume",
        isolated_environment,
        process_runner,
    )

    assert result.status == 0, result
    assert result.stderr == ""
    assert result.stdout == (
        f"[OK] Resumed preparation transaction: {journal['transaction']}\n"
    )
    assert active_issuer.read_text() == active_before
    assert _metadata(active_issuer) == active_metadata
    assert not (workspace.pki / "state/rollover/journal").exists()
    assert not (workspace.pki / "state/rollover/recovery-required").exists()
    assert not (workspace.pki / "state/rollover" / journal["transaction"]).exists()
    candidate = workspace.pki / "authorities/intermediates/g1-i2"
    assert candidate.is_dir() and not candidate.is_symlink()
    long_state = workspace.pki / "state/rollovers" / journal["transaction"]
    assert long_state.is_dir() and not long_state.is_symlink()
    tree_manifest, _ = _read_strict_public_file(long_state / "tree.manifest")
    pointer = _read_strict_record(workspace.pki / "state/active-rollover")
    assert pointer == {
        "transaction": journal["transaction"],
        "tree_manifest_sha256": sha256(tree_manifest).hexdigest(),
    }
    assert _read_strict_record(long_state / "manifest")["transaction"] == (
        journal["transaction"]
    )
    _read_strict_public_file(long_state / "candidate-intermediate-tree.manifest")
