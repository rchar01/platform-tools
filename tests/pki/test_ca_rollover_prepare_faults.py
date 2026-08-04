import os
import shutil
import stat
import tempfile
from collections.abc import Callable, Mapping
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


def _write_executable(path: Path, content: str) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(content)


def _wrapper_directory(tools: RolloverTools, case_name: str) -> Path:
    temporary_root = tools.rollover.parents[1] / ".tmp"
    temporary_root.mkdir(mode=0o700, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix=f"pytest-{case_name}-", dir=temporary_root))


def _read_record(path: Path) -> dict[str, str]:
    return dict(line.split("=", 1) for line in path.read_text().splitlines())


def _prepare_command(
    tools: RolloverTools,
    workspace: RolloverWorkspace,
    receipt: Path,
    rollover_type: str,
) -> list[str | Path]:
    command: list[str | Path] = [
        tools.rollover,
        "prepare",
        "--namespace",
        workspace.namespace,
        "--type",
        rollover_type,
        "--backup-receipt",
        receipt,
    ]
    if rollover_type == "root":
        command.extend(("--root-name", "Test G2 Root CA"))
    command.extend(
        (
            "--intermediate-name",
            (
                "Test G2-I1 Intermediate CA"
                if rollover_type == "root"
                else "Test G1-I2 Intermediate CA"
            ),
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


def _recovery_command(
    tools: RolloverTools,
    workspace: RolloverWorkspace,
    transaction: str,
    action: str,
) -> list[str | Path]:
    return [
        tools.rollover,
        "recover",
        "--namespace",
        workspace.namespace,
        "--transaction",
        transaction,
        "--action",
        action,
        "--yes",
    ]


def _assert_rolled_back(
    workspace: RolloverWorkspace,
    transaction: str,
    active_issuer: bytes,
) -> None:
    assert (workspace.pki / "state/active-issuer").read_bytes() == active_issuer
    assert not (workspace.pki / "state/rollover/journal").exists()
    assert not (workspace.pki / "state/rollover/recovery-required").exists()
    assert not (workspace.pki / f"state/rollover/{transaction}").exists()
    assert not (workspace.pki / "state/active-rollover").exists()
    assert not (workspace.pki / "authorities/roots/g2").exists()
    assert not (workspace.pki / "authorities/intermediates/g1-i2").exists()
    assert not (workspace.pki / "authorities/intermediates/g2-i1").exists()
    assert not tuple(
        (workspace.pki / "state/rollover").glob(
            f".{transaction}.transaction-tree.*"
        )
    )


@pytest.mark.parametrize(
    ("case_name", "rollover_type", "child", "diagnostic"),
    (
        pytest.param(
            "intermediate-child-kill-cp",
            "intermediate",
            "cp",
            "Sensitive child operation failed during copied-root-key",
            id="intermediate-child-kill-cp",
        ),
        pytest.param(
            "intermediate-child-kill-openssl",
            "intermediate",
            "genpkey",
            "Sensitive child operation failed during intermediate-key",
            id="intermediate-child-kill-openssl-genpkey",
        ),
        pytest.param(
            "intermediate-child-kill-openssl-ca",
            "intermediate",
            "ca",
            "Sensitive child operation failed during intermediate-signing",
            id="intermediate-child-kill-openssl-ca",
        ),
        pytest.param(
            "root-child-kill-req",
            "root",
            "req",
            "Sensitive child operation failed during root-certificate",
            id="root-child-kill-req",
        ),
    ),
)
def test_prepare_child_kill_requires_rollback(
    rollover_tools: RolloverTools,
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    private_text_writer: Callable[[Path, str], None],
    process_runner: Callable[..., ProcessResult],
    request: pytest.FixtureRequest,
    case_name: str,
    rollover_type: str,
    child: str,
    diagnostic: str,
) -> None:
    workspace = rollover_case_factory(case_name)
    if rollover_type == "root":
        private_text_writer(
            workspace.private_repo / "pki/trust-consumers.yml",
            VALID_TRUST_CONSUMERS,
        )
    receipt = backup_receipt_factory(workspace)
    active_issuer = (workspace.pki / "state/active-issuer").read_bytes()

    wrapper_directory = _wrapper_directory(rollover_tools, case_name)
    request.addfinalizer(lambda: shutil.rmtree(wrapper_directory))
    cp_wrapper = wrapper_directory / "cp"
    openssl_wrapper = wrapper_directory / "openssl"
    _write_executable(
        cp_wrapper,
        """#!/usr/bin/env bash
"$REAL_CP" "$@" || exit $?
destination=${!#}
[[ ${KILL_CHILD:-} != cp || $destination != */state/rollover/* ]] || kill -KILL "$$"
""",
    )
    _write_executable(
        openssl_wrapper,
        """#!/usr/bin/env bash
subcommand=${1:-}
"$REAL_OPENSSL" "$@" || exit $?
[[ $subcommand != "${KILL_OPENSSL_SUBCOMMAND:-}" ]] || kill -KILL "$$"
""",
    )
    assert stat.S_IMODE(cp_wrapper.stat().st_mode) == 0o700
    assert stat.S_IMODE(openssl_wrapper.stat().st_mode) == 0o700

    environment = dict(isolated_environment)
    environment.update(
        {
            "KILL_OPENSSL_SUBCOMMAND": child,
            "KILL_CHILD": child,
            "PLATFORM_PKI_PREPARE_CP": os.fspath(cp_wrapper),
            "PLATFORM_PKI_PREPARE_OPENSSL": os.fspath(openssl_wrapper),
            "REAL_CP": shutil.which("cp", path=isolated_environment["PATH"])
            or "cp",
            "REAL_OPENSSL": shutil.which(
                "openssl", path=isolated_environment["PATH"]
            )
            or "openssl",
        }
    )
    failed = process_runner(
        _prepare_command(
            rollover_tools, workspace, receipt, rollover_type
        ),
        env=environment,
        timeout=120,
    )

    assert failed.status == 1
    assert failed.stdout == ""
    assert f"[ERROR] {diagnostic}\n" in failed.stderr
    journal = workspace.pki / "state/rollover/journal"
    recovery_marker = workspace.pki / "state/rollover/recovery-required"
    record = _read_record(journal)
    transaction = record["transaction"]
    assert record["operation"] == "rollover-prepare"
    assert record["committed"] == "false"
    assert record["recovery_step"].endswith("-child-failed")
    assert recovery_marker.is_file()
    assert _read_record(recovery_marker)["transaction"] == transaction
    assert (workspace.pki / "state/active-issuer").read_bytes() == active_issuer

    resume = process_runner(
        _recovery_command(
            rollover_tools, workspace, transaction, "resume"
        ),
        env=isolated_environment,
        timeout=120,
    )
    assert resume.status == 1
    assert resume.stdout == ""
    assert resume.stderr == (
        "[ERROR] Preparation interrupted before candidate staging completed; "
        "recover with rollback\n"
    )

    rollback = process_runner(
        _recovery_command(
            rollover_tools, workspace, transaction, "rollback"
        ),
        env=isolated_environment,
        timeout=120,
    )
    assert rollback.status == 0
    assert rollback.stderr == ""
    assert "Rolled back incomplete preparation transaction" in rollback.stdout
    _assert_rolled_back(workspace, transaction, active_issuer)


@pytest.mark.parametrize(
    "boundary",
    (
        pytest.param(
            "transaction-manifest-staged",
            id="transaction-manifest-staged",
        ),
        pytest.param(
            "transaction-manifest-published",
            id="transaction-manifest-published",
        ),
        pytest.param(
            "transaction-manifest-superseded",
            id="transaction-manifest-superseded",
        ),
    ),
)
def test_transaction_manifest_publication_crash_rolls_back(
    rollover_tools: RolloverTools,
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
    boundary: str,
) -> None:
    workspace = rollover_case_factory(boundary)
    receipt = backup_receipt_factory(workspace)
    active_issuer = (workspace.pki / "state/active-issuer").read_bytes()
    environment = dict(isolated_environment)
    environment["PLATFORM_PKI_PREPARE_CRASH_AT"] = boundary

    crashed = process_runner(
        _prepare_command(
            rollover_tools, workspace, receipt, "intermediate"
        ),
        env=environment,
        timeout=120,
    )

    assert crashed.status == 137
    journal = workspace.pki / "state/rollover/journal"
    record = _read_record(journal)
    transaction = record["transaction"]
    pending_manifest = Path(record["transaction_tree_manifest_pending"])
    assert record["transaction_tree_manifest_pending_identity"] != "none"
    assert record["transaction_tree_manifest_pending_sha256"] != "none"
    assert pending_manifest == Path(
        record["transaction_tree_manifest_pending_destination"]
    )
    assert pending_manifest.parent == workspace.pki / "state/rollover"
    assert pending_manifest.is_file()
    assert not pending_manifest.is_symlink()
    assert stat.S_IMODE(pending_manifest.stat().st_mode) == 0o600
    assert (workspace.pki / "state/active-issuer").read_bytes() == active_issuer

    rollback = process_runner(
        _recovery_command(
            rollover_tools, workspace, transaction, "rollback"
        ),
        env=isolated_environment,
        timeout=120,
    )
    assert rollback.status == 0
    assert rollback.stderr == ""
    assert "Rolled back incomplete preparation transaction" in rollback.stdout
    _assert_rolled_back(workspace, transaction, active_issuer)


def test_superseded_manifest_replacement_blocks_pending_promotion(
    rollover_tools: RolloverTools,
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> None:
    workspace = rollover_case_factory("superseded-manifest-replacement")
    receipt = backup_receipt_factory(workspace)
    environment = dict(isolated_environment)
    environment["PLATFORM_PKI_PREPARE_CRASH_AT"] = (
        "transaction-manifest-superseded"
    )
    crashed = process_runner(
        _prepare_command(rollover_tools, workspace, receipt, "intermediate"),
        env=environment,
        timeout=120,
    )

    assert crashed.status == 137
    journal = workspace.pki / "state/rollover/journal"
    record = _read_record(journal)
    current = Path(record["transaction_tree_manifest"])
    pending = Path(record["transaction_tree_manifest_pending"])
    assert not current.exists() and not current.is_symlink()
    assert pending.is_file() and not pending.is_symlink()
    pending_metadata = pending.stat()
    pending_content = pending.read_bytes()
    current.write_text("hostile superseded manifest\n")
    current.chmod(0o600)
    hostile_metadata = current.stat()

    rollback = process_runner(
        _recovery_command(
            rollover_tools,
            workspace,
            record["transaction"],
            "rollback",
        ),
        env=isolated_environment,
        timeout=120,
    )

    assert rollback.status == 1
    assert rollback.stdout == ""
    assert (
        "Preparation transaction manifest changed before cleanup"
        in rollback.stderr
    )
    assert current.read_text() == "hostile superseded manifest\n"
    current_metadata = current.stat()
    assert (
        current_metadata.st_dev,
        current_metadata.st_ino,
        stat.S_IMODE(current_metadata.st_mode),
        current_metadata.st_nlink,
        current_metadata.st_size,
        current_metadata.st_mtime_ns,
    ) == (
        hostile_metadata.st_dev,
        hostile_metadata.st_ino,
        stat.S_IMODE(hostile_metadata.st_mode),
        hostile_metadata.st_nlink,
        hostile_metadata.st_size,
        hostile_metadata.st_mtime_ns,
    )
    assert pending.read_bytes() == pending_content
    current_pending_metadata = pending.stat()
    assert (
        current_pending_metadata.st_dev,
        current_pending_metadata.st_ino,
        stat.S_IMODE(current_pending_metadata.st_mode),
        current_pending_metadata.st_nlink,
        current_pending_metadata.st_size,
        current_pending_metadata.st_mtime_ns,
    ) == (
        pending_metadata.st_dev,
        pending_metadata.st_ino,
        stat.S_IMODE(pending_metadata.st_mode),
        pending_metadata.st_nlink,
        pending_metadata.st_size,
        pending_metadata.st_mtime_ns,
    )
    assert journal.is_file()
