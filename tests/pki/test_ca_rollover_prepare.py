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


def _file_metadata(path: Path) -> tuple[int, int, int, int, int]:
    metadata = path.stat()
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
    )


def _assert_rejected_before_transaction(
    workspace: RolloverWorkspace,
    receipt: Path,
    command: list[str | Path],
    expected_error: str,
    absent_paths: tuple[Path, ...],
    environment: Mapping[str, str],
    public_state_snapshot: Callable[[RolloverWorkspace], tuple[str, ...]],
    process_runner: Callable[..., ProcessResult],
) -> None:
    active_issuer = workspace.pki / "state/active-issuer"
    journal = workspace.pki / "state/rollover/journal"
    issuer_before = active_issuer.read_bytes()
    issuer_metadata_before = _file_metadata(active_issuer)
    journal_before = journal.read_bytes()
    journal_metadata_before = _file_metadata(journal)
    receipt_digest_before = sha256(receipt.read_bytes()).digest()
    receipt_metadata_before = _file_metadata(receipt)
    public_state_before = public_state_snapshot(workspace)

    result = process_runner(command, env=environment, timeout=120)

    assert result.status == 1
    assert result.stdout == ""
    assert result.stderr == f"[ERROR] {expected_error}\n"
    assert public_state_snapshot(workspace) == public_state_before
    assert active_issuer.read_bytes() == issuer_before
    assert _file_metadata(active_issuer) == issuer_metadata_before
    assert journal.read_bytes() == journal_before
    assert _file_metadata(journal) == journal_metadata_before
    assert not (workspace.pki / "state/active-rollover").exists()
    assert not (workspace.pki / "state/rollover/recovery-required").exists()
    assert not tuple((workspace.pki / "state/rollovers").iterdir())
    assert all(not path.exists() for path in absent_paths)
    assert sha256(receipt.read_bytes()).digest() == receipt_digest_before
    assert stat.S_IMODE(receipt.stat().st_mode) == 0o600
    assert _file_metadata(receipt) == receipt_metadata_before


@pytest.mark.parametrize(
    ("case_name", "intermediate_name", "intermediate_days", "expected_error"),
    (
        pytest.param(
            "intermediate-ambiguous-generation-name",
            "Test G1-I20 Intermediate CA",
            None,
            "Intermediate name must identify its new generation ID",
            id="ambiguous-generation-name",
        ),
        pytest.param(
            "intermediate-lifetime-root-margin",
            "Test G1-I2 Intermediate CA",
            3650,
            "Requested intermediate validity exceeds the active root validity safety margin",
            id="lifetime-root-margin",
        ),
    ),
)
def test_intermediate_prepare_rejects_before_transaction(
    rollover_tools: RolloverTools,
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    public_state_snapshot: Callable[[RolloverWorkspace], tuple[str, ...]],
    process_runner: Callable[..., ProcessResult],
    case_name: str,
    intermediate_name: str,
    intermediate_days: int | None,
    expected_error: str,
) -> None:
    workspace = rollover_case_factory(case_name)
    receipt = backup_receipt_factory(workspace)
    command: list[str | Path] = [
        rollover_tools.rollover,
        "prepare",
        "--namespace",
        workspace.namespace,
        "--type",
        "intermediate",
        "--backup-receipt",
        receipt,
        "--intermediate-name",
        intermediate_name,
        "--org",
        "Test",
        "--country",
        "US",
    ]
    if intermediate_days is not None:
        command.extend(("--intermediate-days", str(intermediate_days)))
    command.extend(
        (
            "--root-pass-file",
            workspace.passphrase_file,
            "--intermediate-pass-file",
            workspace.passphrase_file,
        )
    )
    _assert_rejected_before_transaction(
        workspace,
        receipt,
        command,
        expected_error,
        (
            workspace.pki / "state/generation-reservations/g1-i2",
            workspace.pki / "authorities/intermediates/g1-i2",
        ),
        isolated_environment,
        public_state_snapshot,
        process_runner,
    )


@pytest.mark.parametrize(
    ("case_name", "trust_content", "use_symlink", "expected_error"),
    (
        pytest.param(
            "root-symlinked-private-repository",
            VALID_TRUST_CONSUMERS,
            True,
            None,
            id="symlinked-private-repository",
        ),
        pytest.param(
            "root-invalid-trust-consumer-grammar",
            "consumers:\n  invalid:\n    unknown: manual\n",
            False,
            "Unsupported trust consumer grammar at line 3",
            id="invalid-trust-consumer-grammar",
        ),
        pytest.param(
            "root-duplicate-yaml-document-marker",
            "---\n---\nconsumers:\n  invalid:\n    kind: manual\n",
            False,
            "Trust consumer document marker is duplicate or misplaced at line 2",
            id="duplicate-yaml-document-marker",
        ),
    ),
)
def test_root_prepare_rejects_before_transaction(
    rollover_tools: RolloverTools,
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    private_text_writer: Callable[[Path, str], None],
    public_state_snapshot: Callable[[RolloverWorkspace], tuple[str, ...]],
    process_runner: Callable[..., ProcessResult],
    case_name: str,
    trust_content: str,
    use_symlink: bool,
    expected_error: str | None,
) -> None:
    workspace = rollover_case_factory(case_name)
    trust_source = workspace.private_repo / "pki/trust-consumers.yml"
    private_text_writer(trust_source, VALID_TRUST_CONSUMERS)
    receipt = backup_receipt_factory(workspace)
    trust_source.write_text(trust_content)
    trust_source_before = trust_source.read_bytes()
    trust_source_metadata_before = _file_metadata(trust_source)

    private_repo = workspace.private_repo
    if use_symlink:
        private_repo = workspace.root / "private-link"
        private_repo.symlink_to(workspace.private_repo, target_is_directory=True)
        expected_error = (
            "Private repository path component must not be a symlink: "
            f"{private_repo}"
        )

    command: list[str | Path] = [
        rollover_tools.rollover,
        "prepare",
        "--namespace",
        workspace.namespace,
        "--type",
        "root",
        "--backup-receipt",
        receipt,
        "--root-name",
        "Test G2 Root CA",
        "--intermediate-name",
        "Test G2-I1 Intermediate CA",
        "--org",
        "Test",
        "--country",
        "US",
        "--root-pass-file",
        workspace.passphrase_file,
        "--intermediate-pass-file",
        workspace.passphrase_file,
        "--private-repo",
        private_repo,
    ]
    assert expected_error is not None
    _assert_rejected_before_transaction(
        workspace,
        receipt,
        command,
        expected_error,
        (
            workspace.pki / "state/generation-reservations/g2",
            workspace.pki / "state/generation-reservations/g2-i1",
            workspace.pki / "authorities/roots/g2",
            workspace.pki / "authorities/intermediates/g2-i1",
        ),
        isolated_environment,
        public_state_snapshot,
        process_runner,
    )
    assert trust_source.read_bytes() == trust_source_before
    assert _file_metadata(trust_source) == trust_source_metadata_before
    if use_symlink:
        assert private_repo.is_symlink()
        assert private_repo.readlink() == workspace.private_repo
