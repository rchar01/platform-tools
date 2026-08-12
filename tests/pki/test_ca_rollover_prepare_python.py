from __future__ import annotations

import os
import re
import sys
from collections.abc import Callable, Mapping
from dataclasses import replace
from pathlib import Path

import pytest

from src.platform_pki.ca_rollover_prepare import (
    _initial_values,
    _validate_trust_consumers,
)
from src.platform_pki.ca_rollover_recovery import (
    ROLLOVER_PREPARE_RUNTIME_IDENTITY_FIELDS,
    RecoveryRecordError,
    parse_preparation_terminal_receipt,
    serialize_typed_recovery_rewrite,
)
from src.platform_pki.errors import ApplicationError
from src.platform_pki.filesystem import identity_from_stat
from src.platform_pki.persisted_identity import serialize_file_identity

from ..harness import ProcessResult
from .conftest import RolloverTools, RolloverWorkspace
from .migration_harness import run_differential_case
from .test_ca_rollover_prepare import VALID_TRUST_CONSUMERS
from .test_ca_rollover_prepare_recovery import (
    INTERMEDIATE_EARLY_CHECKPOINTS,
    PRESENT_ROOT_DB_KEYS,
    ROOT_CRYPTO_CHECKPOINTS,
    ROOT_DB_RELATIVES,
    _read_strict_record,
)
from .test_ca_rollover_python_recover import (
    _PREPARATION_NORMALIZATION,
    _create_backup,
    _normalize_recovery_output,
    _rebase_seed_configs,
    _recovery_content_normalizer,
    _replace_dynamic_tokens,
)


pytestmark = pytest.mark.pki

REPOSITORY = Path(__file__).resolve().parents[2]
ORACLE = (
    REPOSITORY
    / "tests/pki/oracles/platform-pki-ca-rollover/platform-pki-ca-rollover"
)
DRIVER = REPOSITORY / "tests/pki/ca_rollover_prepare_driver.py"
_TRANSACTION = re.compile(r"prepare-intermediate-[0-9]{8}-[0-9]{6}-[0-9]+")
_CERTIFICATION_EXPIRY = re.compile(
    r"(?<=Certificate is to be certified until ).+(?= \([0-9]+ days\))"
)
_INTERMEDIATE_WRITER_CHECKPOINTS = (
    "transaction-manifest-staged",
    "transaction-manifest-published",
    "transaction-manifest-superseded",
    "after-journal",
    "after-transaction",
    "after-reservations",
    "after-staged",
    "after-intermediate-candidate",
    "after-root-db",
    "after-consumed",
    "cleanup-root-stage-removed",
    "after-state",
    "after-pointer",
    "long-stage-created",
    "intermediate-signing-db-ready",
    "long-stage-pending",
    "long-stage-done",
    "sensitive-stage-pending",
    "sensitive-stage-done",
    "intermediate-key-done",
    "intermediate-csr-done",
    "intermediate-signing-done",
    "chain-done",
    *(
        f"{base}-{phase}"
        for base in (
            "transaction-dir",
            "backup-session",
            "reserve-intermediate",
            "stage-dir",
            "sensitive-root-stage",
            "sensitive-root-private",
            "sensitive-intermediate-stage",
            "sensitive-intermediate-private",
            "intermediate-stage-config",
            "evidence-stage",
            "publish-intermediate",
            "consume-intermediate",
            "cleanup-root-stage",
            "publish-state",
            "publish-pointer",
        )
        for phase in ("pending", "done")
    ),
    *(
        f"{base}-{phase}"
        for base in (
            "copied-root-key",
            "copied-root-cert",
            *(f"copied-root-{key}" for key in ROOT_DB_RELATIVES if key in {"index", "index_attr", "serial", "crlnumber"}),
            *(f"backup-root-{key}" for key in ROOT_DB_RELATIVES if key != "newcert"),
        )
        for phase in ("pending", "done")
    ),
    "intermediate-key-pending",
    "intermediate-csr-pending",
    "intermediate-signing-pending",
    "chain-pending",
    *(
        f"publish-root-db-{key}-{phase}"
        for key in ROOT_DB_RELATIVES
        for phase in ("pending", "done")
    ),
)
_ROOT_WRITER_CHECKPOINTS = (
    "candidate-root-stage-pending",
    "root-key-pending",
    "root-certificate-done",
    "intermediate-key-pending",
    "intermediate-signing-done",
    "evidence-stage-done",
    "publish-root-pending",
    "publish-intermediate-pending",
    "consume-root-pending",
    "publish-state-pending",
    "publish-pointer-pending",
    "terminal-publication-pending",
)
_ROOT_PREPARATION_NORMALIZATION = replace(
    _PREPARATION_NORMALIZATION,
    tokens=(
        (
            re.compile(r"prepare-root-[0-9]{8}-[0-9]{6}-[0-9]+"),
            "<INTERMEDIATE-PREPARATION>",
        ),
        *_PREPARATION_NORMALIZATION.tokens[1:],
    ),
    generated_paths=(
        re.compile(
            r"authorities/(?:roots/g2|intermediates/g2-i1)/(?:certs/(?:root-ca|"
            r"intermediate-ca|ca-chain)\.crt|csr/intermediate-ca\.csr|private/"
            r"(?:root-ca|intermediate-ca)\.key)"
        ),
        re.compile(r"authorities/roots/g2/(?:index\.txt|newcerts/[^/]+\.pem)"),
        re.compile(
            r"state/rollover/<INTERMEDIATE-PREPARATION>/stage/(?:root|intermediate)/"
            r"(?:certs/(?:root-ca|intermediate-ca|ca-chain)\.crt|csr/"
            r"intermediate-ca\.csr|private/(?:root-ca|intermediate-ca)\.key)"
        ),
    ),
    dynamic_text_paths=(
        re.compile(r"authorities/(?:roots/g2|intermediates/g2-i1)/openssl\.cnf"),
        re.compile(
            r"state/rollover/<INTERMEDIATE-PREPARATION>/stage/"
            r"(?:root|intermediate)/openssl\.cnf"
        ),
    ),
    dynamic_fields=_PREPARATION_NORMALIZATION.dynamic_fields
    | frozenset(
        {
            "candidate_root_cert_sha256",
            "candidate_root_expiry",
            "candidate_root_fingerprint",
            "candidate_root_tree_manifest_sha256",
            "candidate_root_tree_sha256",
            "root_expiry",
            "root_fingerprint",
        }
    ),
    manifest_paths=tuple(
        re.compile(pattern.pattern.replace("candidate-intermediate", "candidate-(?:root|intermediate)"))
        for pattern in _PREPARATION_NORMALIZATION.manifest_paths
    ),
    generated_manifest_rows=(
        *_PREPARATION_NORMALIZATION.generated_manifest_rows,
        re.compile(
            r"(?:(?:stage/)?root/)?(?:certs/root-ca\.crt|private/root-ca\.key)"
        ),
        re.compile(r"(?:rollover-state/)?candidate-root-tree\.manifest"),
    ),
)


def _terminal_receipt(workspace: RolloverWorkspace, transaction: str) -> dict[str, str]:
    path = workspace.pki / "state/rollover" / f"terminal-{transaction}"
    values = _read_strict_record(path)
    parsed = parse_preparation_terminal_receipt(path.read_bytes())
    assert parsed.transaction == transaction
    assert parsed.outcome.value == values["terminal_outcome"]
    return values


def _full_identity(path: Path) -> str:
    return serialize_file_identity(identity_from_stat(path.lstat()))


def _arguments(
    workspace: RolloverWorkspace, receipt: Path, generation: int = 2
) -> list[str | Path]:
    return [
        "--namespace",
        workspace.namespace,
        "--type",
        "intermediate",
        "--backup-receipt",
        receipt,
        "--intermediate-name",
        f"Python Prepare G1-I{generation} Intermediate CA",
        "--org",
        "Test",
        "--country",
        "US",
        "--root-pass-file",
        workspace.passphrase_file,
        "--intermediate-pass-file",
        workspace.passphrase_file,
    ]


def _root_arguments(
    workspace: RolloverWorkspace, receipt: Path
) -> list[str | Path]:
    arguments = _arguments(workspace, receipt)
    type_index = arguments.index("intermediate")
    arguments[type_index] = "root"
    name_index = arguments.index("Python Prepare G1-I2 Intermediate CA")
    arguments[name_index] = "Python Prepare G2-I1 Intermediate CA"
    arguments.extend(
        (
            "--root-name",
            "Python Prepare G2 Root CA",
            "--private-repo",
            workspace.private_repo,
        )
    )
    return arguments


def _workspace(root: Path) -> RolloverWorkspace:
    return RolloverWorkspace(
        root=root,
        namespace=root / "ns",
        pki=root / "ns/pki",
        private_repo=root / "private",
        passphrase_file=root / "passphrase",
    )


def _differential_receipt(root: Path) -> Path:
    receipts = tuple((root / "differential-backups").glob("*.receipt"))
    assert len(receipts) == 1
    return receipts[0]


@pytest.mark.parametrize(
    "byte",
    (*tuple(value for value in range(0x20) if value != 0x0A), *range(0x7F, 0xA0)),
)
def test_trust_consumer_parser_rejects_every_control_byte(byte: int) -> None:
    data = b"consumers:\n  managed:\n    kind: managed" + bytes((byte,)) + b"\n"

    with pytest.raises(
        ApplicationError,
        match=r"Trust consumer checklist contains unsupported characters at line 3",
    ):
        _validate_trust_consumers(data)


def test_trust_consumer_parser_accepts_only_lf_line_endings() -> None:
    _validate_trust_consumers(VALID_TRUST_CONSUMERS.encode("ascii"))
    with pytest.raises(ApplicationError, match="unsupported characters at line 1"):
        _validate_trust_consumers(VALID_TRUST_CONSUMERS.replace("\n", "\r\n").encode("ascii"))


def test_schema5_runtime_identity_variants_are_strictly_cumulative(
    tmp_path: Path,
) -> None:
    pki = tmp_path / "pki"
    pki.mkdir()
    (pki / "state").mkdir()
    (pki / "state/rollover").mkdir()
    identity_path = tmp_path / "identity"
    identity_path.write_text("identity\n", encoding="ascii")
    identity_path.chmod(0o600)
    identity = identity_from_stat(identity_path.lstat())
    identity_text = serialize_file_identity(identity)
    values = _initial_values(
        pki_dir=os.fspath(pki),
        preparation_type="intermediate",
        transaction="prepare-intermediate-20260812-120000-1",
        active_root="g1",
        active_intermediate="g1-i1",
        active_manifest=os.fspath(pki / "state/active-issuer"),
        active_identity=identity,
        candidate_root="g1",
        candidate_intermediate="g1-i2",
        backup_receipt=os.fspath(tmp_path / "backup.receipt"),
        receipt_identity=identity,
        receipt={"session": "0" * 32},
        trust_source="none",
        trust_source_identity=None,
        trust_snapshot_sha256="none",
    )
    execution_order = (
        "root_stage_cert_identity",
        "root_stage_index_identity",
        "root_stage_index_backup_identity",
        "root_stage_index_attr_identity",
        "root_stage_index_attr_backup_identity",
        "root_stage_serial_identity",
        "root_stage_serial_backup_identity",
        "root_stage_crlnumber_identity",
        "root_stage_crlnumber_backup_identity",
        "root_stage_index_old_backup_identity",
        "root_stage_index_attr_old_backup_identity",
        "root_stage_serial_old_backup_identity",
        "root_stage_crlnumber_old_backup_identity",
    )
    assert frozenset(execution_order) == frozenset(
        ROLLOVER_PREPARE_RUNTIME_IDENTITY_FIELDS
    )

    for field in execution_order:
        prefix = field.removesuffix("_identity")
        values[f"{prefix}_pre_identity"] = identity_text
        values[field] = identity_text
        serialize_typed_recovery_rewrite(values, pki_dir=pki)

    noncumulative = dict(values)
    del noncumulative[execution_order[4]]
    with pytest.raises(RecoveryRecordError, match="not cumulative"):
        serialize_typed_recovery_rewrite(noncumulative, pki_dir=pki)


@pytest.mark.parametrize("checkpoint", _INTERMEDIATE_WRITER_CHECKPOINTS)
def test_python_prepare_all_normal_path_checkpoints_roll_back(
    rollover_tools: RolloverTools,
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
    checkpoint: str,
) -> None:
    assert set(INTERMEDIATE_EARLY_CHECKPOINTS) <= set(
        _INTERMEDIATE_WRITER_CHECKPOINTS
    )
    workspace = rollover_case_factory(f"python-prepare-checkpoint-{checkpoint}")
    (workspace.pki / "state/rollover/journal").unlink(missing_ok=True)
    if checkpoint.startswith("backup-root-crlnumber_old-"):
        optional = workspace.pki / "authorities/roots/g1/crlnumber.old"
        optional.write_text("pre-transaction-crlnumber-old\n", encoding="ascii")
        optional.chmod(0o600)
    receipt = backup_receipt_factory(workspace)
    environment = dict(isolated_environment)
    environment["PLATFORM_PKI_PREPARE_CRASH_AT"] = checkpoint
    if checkpoint.startswith("publish-root-db-crlnumber_old-"):
        environment.update(
            PLATFORM_PKI_PREPARE_DRIVER_MUTATE_AT="intermediate-signing-db-ready",
            PLATFORM_PKI_PREPARE_DRIVER_MUTATE_PATH=os.fspath(
                workspace.pki
                / "state/rollover/{transaction}/stage/root/crlnumber.old"
            ),
        )

    crashed = process_runner(
        [sys.executable, DRIVER, *_arguments(workspace, receipt)],
        env=environment,
        timeout=120,
    )

    assert crashed.status == 137, crashed
    journal = _read_strict_record(workspace.pki / "state/rollover/journal")
    recovered = process_runner(
        [
            rollover_tools.rollover,
            "recover",
            "--namespace",
            workspace.namespace,
            "--transaction",
            journal["transaction"],
            "--action",
            "rollback",
            "--yes",
        ],
        env=isolated_environment,
        timeout=120,
    )
    assert recovered.status == 0, recovered
    terminal = _terminal_receipt(workspace, journal["transaction"])
    assert terminal["terminal_outcome"] == "rolled-back"
    assert not (workspace.pki / "state/rollover/journal").exists()
    assert not (workspace.pki / "state/rollover/recovery-required").exists()


@pytest.mark.parametrize("checkpoint", _ROOT_WRITER_CHECKPOINTS)
def test_python_root_prepare_bounded_checkpoints_roll_back(
    rollover_tools: RolloverTools,
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    private_text_writer: Callable[[Path, str], None],
    process_runner: Callable[..., ProcessResult],
    checkpoint: str,
) -> None:
    assert set(ROOT_CRYPTO_CHECKPOINTS) & set(_ROOT_WRITER_CHECKPOINTS)
    workspace = rollover_case_factory(f"python-root-prepare-checkpoint-{checkpoint}")
    (workspace.pki / "state/rollover/journal").unlink(missing_ok=True)
    private_text_writer(
        workspace.private_repo / "pki/trust-consumers.yml", VALID_TRUST_CONSUMERS
    )
    receipt = backup_receipt_factory(workspace)
    environment = dict(isolated_environment)
    environment["PLATFORM_PKI_PREPARE_CRASH_AT"] = checkpoint

    crashed = process_runner(
        [sys.executable, DRIVER, *_root_arguments(workspace, receipt)],
        env=environment,
        timeout=120,
    )

    assert crashed.status == 137, crashed
    journal = _read_strict_record(workspace.pki / "state/rollover/journal")
    recovered = process_runner(
        [
            rollover_tools.rollover,
            "recover",
            "--namespace",
            workspace.namespace,
            "--transaction",
            journal["transaction"],
            "--action",
            "rollback",
            "--yes",
        ],
        env=isolated_environment,
        timeout=120,
    )
    assert recovered.status == 0, recovered
    assert _terminal_receipt(workspace, journal["transaction"])[
        "terminal_outcome"
    ] == "rolled-back"


@pytest.mark.parametrize(
    ("mode", "checkpoint", "status"),
    (
        ("FAIL", "intermediate-key-pending", 1),
        ("FAIL", "publish-state-pending", 1),
        ("SIGNAL", "intermediate-key-pending", 143),
        ("SIGNAL", "publish-state-pending", 143),
    ),
)
def test_python_prepare_fault_and_signal_checkpoints_are_recoverable(
    rollover_tools: RolloverTools,
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
    mode: str,
    checkpoint: str,
    status: int,
) -> None:
    workspace = rollover_case_factory(
        f"python-prepare-{mode.lower()}-{checkpoint}"
    )
    (workspace.pki / "state/rollover/journal").unlink(missing_ok=True)
    receipt = backup_receipt_factory(workspace)
    environment = dict(isolated_environment)
    environment[f"PLATFORM_PKI_PREPARE_{mode}_AT"] = checkpoint

    interrupted = process_runner(
        [sys.executable, DRIVER, *_arguments(workspace, receipt)],
        env=environment,
        timeout=120,
    )

    assert interrupted.status == status, interrupted
    journal = _read_strict_record(workspace.pki / "state/rollover/journal")
    recovered = process_runner(
        [
            rollover_tools.rollover,
            "recover",
            "--namespace",
            workspace.namespace,
            "--transaction",
            journal["transaction"],
            "--action",
            "rollback",
            "--yes",
        ],
        env=isolated_environment,
        timeout=120,
    )
    assert recovered.status == 0, recovered
    assert _terminal_receipt(workspace, journal["transaction"])[
        "terminal_outcome"
    ] == "rolled-back"


@pytest.mark.parametrize("writer", ("oracle", "python"))
def test_prepare_writer_publishes_schema5_recoverable_state(
    rollover_tools: RolloverTools,
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
    writer: str,
) -> None:
    workspace = rollover_case_factory(f"python-prepare-{writer}")
    (workspace.pki / "state/rollover/journal").unlink(missing_ok=True)
    receipt = backup_receipt_factory(workspace)
    environment = dict(isolated_environment)
    if writer == "oracle":
        command = [ORACLE, "prepare", *_arguments(workspace, receipt)]
        environment["PLATFORM_TOOLS_LIB_DIR"] = os.fspath(ORACLE.parent / "lib")
    else:
        command = [sys.executable, DRIVER, *_arguments(workspace, receipt)]
    environment["PLATFORM_PKI_PREPARE_CRASH_AT"] = "after-staged"

    result = process_runner(command, env=environment, timeout=120)

    assert result.status == 137, result
    journal = _read_strict_record(workspace.pki / "state/rollover/journal")
    assert journal["schema"] == "5"
    assert journal["operation"] == "rollover-prepare"
    assert journal["phase"] == "staged"
    assert journal["recovery_step"] == "evidence-stage-done"
    assert _TRANSACTION.fullmatch(journal["transaction"])
    assert (Path(journal["stage_dir"]) / "intermediate").is_dir()
    assert Path(journal["root_stage"]).is_dir()

    recovery = process_runner(
        [
            rollover_tools.rollover,
            "recover",
            "--namespace",
            workspace.namespace,
            "--transaction",
            journal["transaction"],
            "--action",
            "resume",
            "--yes",
        ],
        env=isolated_environment,
        timeout=120,
    )
    assert recovery.status == 0, recovery
    assert (workspace.pki / "state/active-rollover").is_file()
    terminal = _terminal_receipt(workspace, journal["transaction"])
    assert terminal["terminal_outcome"] == "resumed"
    assert terminal["operation"] == "rollover-prepare"


@pytest.mark.parametrize(
    ("rollover_type", "checkpoint", "recovery_step"),
    (
        ("root", "after-root-candidate", "publish-root-done"),
        (
            "intermediate",
            "after-intermediate-candidate",
            "publish-intermediate-done",
        ),
        ("intermediate", "after-root-db", "publish-root-db-newcert-done"),
    ),
)
def test_python_prepare_writer_resumes_after_publication(
    rollover_tools: RolloverTools,
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    private_text_writer: Callable[[Path, str], None],
    process_runner: Callable[..., ProcessResult],
    rollover_type: str,
    checkpoint: str,
    recovery_step: str,
) -> None:
    workspace = rollover_case_factory(f"python-prepare-resume-{checkpoint}")
    (workspace.pki / "state/rollover/journal").unlink(missing_ok=True)
    if rollover_type == "root":
        private_text_writer(
            workspace.private_repo / "pki/trust-consumers.yml",
            VALID_TRUST_CONSUMERS,
        )
    receipt = backup_receipt_factory(workspace)
    arguments = (
        _root_arguments(workspace, receipt)
        if rollover_type == "root"
        else _arguments(workspace, receipt)
    )
    environment = dict(isolated_environment)
    environment["PLATFORM_PKI_PREPARE_CRASH_AT"] = checkpoint

    result = process_runner(
        [sys.executable, DRIVER, *arguments],
        env=environment,
        timeout=120,
    )

    assert result.status == 137, result
    journal = _read_strict_record(workspace.pki / "state/rollover/journal")
    assert journal["phase"] == "recovering"
    assert journal["recovery_step"] == recovery_step
    recovery = process_runner(
        [
            rollover_tools.rollover,
            "recover",
            "--namespace",
            workspace.namespace,
            "--transaction",
            journal["transaction"],
            "--action",
            "resume",
            "--yes",
        ],
        env=isolated_environment,
        timeout=120,
    )

    assert recovery.status == 0, recovery
    assert not (workspace.pki / "state/rollover/journal").exists()
    assert (workspace.pki / "state/active-rollover").is_file()
    assert (
        workspace.pki
        / "authorities/intermediates"
        / journal["candidate_intermediate"]
    ).is_dir()
    if rollover_type == "root":
        assert (
            workspace.pki / "authorities/roots" / journal["candidate_root"]
        ).is_dir()
    terminal = _terminal_receipt(workspace, journal["transaction"])
    assert terminal["terminal_outcome"] == "resumed"


@pytest.mark.parametrize("rollover_type", ("intermediate", "root"))
def test_python_prepare_writer_completes(
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    private_text_writer: Callable[[Path, str], None],
    process_runner: Callable[..., ProcessResult],
    rollover_type: str,
) -> None:
    workspace = rollover_case_factory(f"python-prepare-complete-{rollover_type}")
    (workspace.pki / "state/rollover/journal").unlink(missing_ok=True)
    if rollover_type == "root":
        private_text_writer(
            workspace.private_repo / "pki/trust-consumers.yml",
            VALID_TRUST_CONSUMERS,
        )
    receipt = backup_receipt_factory(workspace)
    arguments = (
        _root_arguments(workspace, receipt)
        if rollover_type == "root"
        else _arguments(workspace, receipt)
    )

    result = process_runner(
        [sys.executable, DRIVER, *arguments],
        env=isolated_environment,
        timeout=120,
    )

    assert result.status == 0, result
    match = re.fullmatch(
        rf"\[OK\] Prepared {rollover_type} rollover transaction "
        r"(?P<transaction>prepare-(?:root|intermediate)-[0-9]{8}-[0-9]{6}-[0-9]+) "
        r"with candidate (?P<root>g[1-9][0-9]*)/"
        r"(?P<intermediate>g[1-9][0-9]*-i[1-9][0-9]*)\n",
        result.stdout,
    )
    assert match is not None
    assert not (workspace.pki / "state/rollover/journal").exists()
    assert not (workspace.pki / "state/rollover/recovery-required").exists()
    assert not (workspace.pki / "state/rollover" / match["transaction"]).exists()
    assert (workspace.pki / "state/active-rollover").is_file()
    assert (workspace.pki / "state/rollovers" / match["transaction"]).is_dir()
    assert (
        workspace.pki / "authorities/intermediates" / match["intermediate"]
    ).is_dir()
    if rollover_type == "root":
        assert (workspace.pki / "authorities/roots" / match["root"]).is_dir()
    terminal = _terminal_receipt(workspace, match["transaction"])
    assert terminal["terminal_outcome"] == "resumed"


def test_root_database_pre_sign_snapshot_is_not_recaptured(
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> None:
    workspace = rollover_case_factory("python-prepare-pre-sign-snapshot")
    (workspace.pki / "state/rollover/journal").unlink(missing_ok=True)
    receipt = backup_receipt_factory(workspace)
    root = workspace.pki / "authorities/roots/g1"
    before = {
        key: (
            "absent"
            if not (path := root / relative).exists()
            else _full_identity(path)
        )
        for key, relative in ROOT_DB_RELATIVES.items()
        if key != "newcert"
    }
    environment = dict(isolated_environment)
    environment.update(
        PLATFORM_PKI_PREPARE_DRIVER_MUTATE_AT="intermediate-signing-db-ready",
        PLATFORM_PKI_PREPARE_DRIVER_MUTATE_PATH=os.fspath(root / "serial"),
        PLATFORM_PKI_PREPARE_CRASH_AT="after-staged",
    )

    result = process_runner(
        [sys.executable, DRIVER, *_arguments(workspace, receipt)],
        env=environment,
        timeout=120,
    )

    assert result.status == 137, result
    journal = _read_strict_record(workspace.pki / "state/rollover/journal")
    assert journal["root_serial_pre_identity"] == before["serial"]
    assert journal["root_serial_pre_identity"] != _full_identity(root / "serial")
    for key, expected in before.items():
        assert journal[f"root_{key}_pre_identity"] == expected
    assert journal["root_newcert_pre_identity"] == "absent"


def test_root_database_absent_entry_cannot_appear_before_snapshot_finalization(
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> None:
    workspace = rollover_case_factory("python-prepare-root-db-absent-race")
    (workspace.pki / "state/rollover/journal").unlink(missing_ok=True)
    receipt = backup_receipt_factory(workspace)
    path = workspace.pki / "authorities/roots/g1/crlnumber.old"
    assert not path.exists()
    environment = dict(isolated_environment)
    environment.update(
        PLATFORM_PKI_PREPARE_DRIVER_MUTATE_AT="root-db-snapshot-ready",
        PLATFORM_PKI_PREPARE_DRIVER_MUTATE_PATH=os.fspath(path),
    )

    result = process_runner(
        [sys.executable, DRIVER, *_arguments(workspace, receipt)],
        env=environment,
        timeout=120,
    )

    assert result.status == 1, result
    assert result.stdout == ""
    assert "Root database source changed during rollover preparation" in result.stderr


@pytest.mark.parametrize(
    ("rollover_type", "point"),
    (
        ("root", "publish-root-pending"),
        ("root", "publish-intermediate-pending"),
        ("intermediate", "publish-root-db-index-pending"),
        ("intermediate", "publish-state-pending"),
        ("intermediate", "publish-pointer-pending"),
        ("intermediate", "terminal-publication-pending"),
        ("intermediate", "terminal-marker-publication"),
        ("intermediate", "terminal-receipt-publication"),
    ),
)
def test_each_publication_family_rechecks_authorization_sources(
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    private_text_writer: Callable[[Path, str], None],
    process_runner: Callable[..., ProcessResult],
    rollover_type: str,
    point: str,
) -> None:
    workspace = rollover_case_factory(f"python-prepare-source-recheck-{point}")
    (workspace.pki / "state/rollover/journal").unlink(missing_ok=True)
    if rollover_type == "root":
        private_text_writer(
            workspace.private_repo / "pki/trust-consumers.yml",
            VALID_TRUST_CONSUMERS,
        )
    receipt = backup_receipt_factory(workspace)
    arguments = (
        _root_arguments(workspace, receipt)
        if rollover_type == "root"
        else _arguments(workspace, receipt)
    )
    environment = dict(isolated_environment)
    environment.update(
        PLATFORM_PKI_PREPARE_DRIVER_MUTATE_AT=point,
        PLATFORM_PKI_PREPARE_DRIVER_MUTATE_PATH=os.fspath(
            workspace.pki / "inventory/services.yml"
        ),
    )

    result = process_runner(
        [sys.executable, DRIVER, *arguments], env=environment, timeout=120
    )

    assert result.status == 1, result
    assert result.stdout == ""
    assert "Service inventory changed during rollover preparation" in result.stderr


@pytest.mark.parametrize("key", PRESENT_ROOT_DB_KEYS)
def test_root_database_publication_rechecks_exact_pre_state(
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
    key: str,
) -> None:
    workspace = rollover_case_factory(f"python-prepare-root-db-recheck-{key}")
    (workspace.pki / "state/rollover/journal").unlink(missing_ok=True)
    receipt = backup_receipt_factory(workspace)
    root = workspace.pki / "authorities/roots/g1"
    if key == "newcert":
        path = root / "newcerts/{issued_serial}.pem"
    else:
        path = root / ROOT_DB_RELATIVES[key]
    environment = dict(isolated_environment)
    environment.update(
        PLATFORM_PKI_PREPARE_DRIVER_MUTATE_AT=f"publish-root-db-{key}-pending",
        PLATFORM_PKI_PREPARE_DRIVER_MUTATE_PATH=os.fspath(path),
    )

    result = process_runner(
        [sys.executable, DRIVER, *_arguments(workspace, receipt)],
        env=environment,
        timeout=120,
    )

    assert result.status == 1, result
    assert result.stdout == ""
    assert f"Root {key} identity changed before publication" in result.stderr
    journal = _read_strict_record(workspace.pki / "state/rollover/journal")
    assert journal["recovery_step"] == f"publish-root-db-{key}-pending"


@pytest.mark.parametrize(
    ("point", "relative", "message"),
    (
        (
            "publish-state-pending",
            "state/rollovers/{transaction}",
            "Rollover state identity changed before publication",
        ),
        (
            "publish-pointer-pending",
            "state/active-rollover",
            "Active rollover pointer identity changed before publication",
        ),
    ),
)
def test_final_publications_recheck_exact_absence(
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
    point: str,
    relative: str,
    message: str,
) -> None:
    workspace = rollover_case_factory(f"python-prepare-final-recheck-{point}")
    (workspace.pki / "state/rollover/journal").unlink(missing_ok=True)
    receipt = backup_receipt_factory(workspace)
    environment = dict(isolated_environment)
    environment.update(
        PLATFORM_PKI_PREPARE_DRIVER_MUTATE_AT=point,
        PLATFORM_PKI_PREPARE_DRIVER_MUTATE_PATH=os.fspath(workspace.pki / relative),
    )

    result = process_runner(
        [sys.executable, DRIVER, *_arguments(workspace, receipt)],
        env=environment,
        timeout=120,
    )

    assert result.status == 1, result
    assert result.stdout == ""
    assert message in result.stderr


@pytest.mark.parametrize("rollover_type", ("intermediate", "root"))
def test_passphrases_cross_only_applicable_openssl_descriptor_channels(
    tmp_path: Path,
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    private_text_writer: Callable[[Path, str], None],
    process_runner: Callable[..., ProcessResult],
    rollover_type: str,
) -> None:
    workspace = rollover_case_factory(
        f"python-prepare-passphrase-boundary-{rollover_type}"
    )
    (workspace.pki / "state/rollover/journal").unlink(missing_ok=True)
    if rollover_type == "root":
        private_text_writer(
            workspace.private_repo / "pki/trust-consumers.yml",
            VALID_TRUST_CONSUMERS,
        )
    receipt = backup_receipt_factory(workspace)
    intermediate_passphrase = tmp_path / "intermediate-passphrase"
    intermediate_passphrase.write_bytes(workspace.passphrase_file.read_bytes())
    intermediate_passphrase.chmod(0o600)
    log = tmp_path / "openssl-boundary.log"
    wrapper = tmp_path / "openssl"
    wrapper.write_text(
        f"""#!/usr/bin/env python3
import os
import pathlib
import sys

REAL = '/usr/bin/openssl'
ROOT_PATH = {os.fspath(workspace.passphrase_file)!r}
INTERMEDIATE_PATH = {os.fspath(intermediate_passphrase)!r}
SECRET = {workspace.passphrase_file.read_text()!r}
LOG = {os.fspath(log)!r}
arguments = sys.argv[1:]
joined = '\\0'.join(arguments) + '\\0' + '\\0'.join(f'{{k}}={{v}}' for k, v in os.environ.items())
if ROOT_PATH in joined or INTERMEDIATE_PATH in joined or SECRET.strip() in joined:
    raise SystemExit(91)
sensitive = {{}}
for entry in pathlib.Path('/proc/self/fd').iterdir():
    try:
        descriptor = int(entry.name)
        if os.path.samefile(entry, ROOT_PATH):
            sensitive[descriptor] = 'root'
        elif os.path.samefile(entry, INTERMEDIATE_PATH):
            sensitive[descriptor] = 'intermediate'
    except (FileNotFoundError, OSError, ValueError):
        pass
command = arguments[0]
expected = {{'ca': ('root', '-passin')}}.get(command)
if command == 'genpkey':
    expected = ('root' if '/stage/root/' in arguments[arguments.index('-out') + 1] else 'intermediate', '-pass')
elif command == 'req':
    expected = ('root' if '/stage/root/' in arguments[arguments.index('-key') + 1] else 'intermediate', '-passin')
if command == 'pkey' and '-in' in arguments:
    expected = ('root' if '/stage/root/' in arguments[arguments.index('-in') + 1] else 'intermediate', '-passin')
tokens = [argument for argument in arguments if argument.startswith('fd:')]
if expected is None:
    if sensitive or tokens:
        raise SystemExit(92)
elif len(sensitive) != 1 or len(tokens) != 1 or expected[1] not in arguments:
    raise SystemExit(93)
elif arguments[arguments.index(expected[1]) + 1] != tokens[0] or sensitive.get(int(tokens[0][3:])) != expected[0]:
    raise SystemExit(94)
elif os.pread(int(tokens[0][3:]), 4096, 0).decode() != SECRET:
    raise SystemExit(95)
with open(LOG, 'a', encoding='ascii') as stream:
    stream.write(f'{{command}}:{{next(iter(sensitive.values()), "none")}}\\n')
os.execv(REAL, [REAL, *arguments])
""",
        encoding="ascii",
    )
    wrapper.chmod(0o700)
    environment = dict(isolated_environment)
    environment["PLATFORM_PKI_PREPARE_OPENSSL"] = os.fspath(wrapper)

    arguments = (
        _root_arguments(workspace, receipt)
        if rollover_type == "root"
        else _arguments(workspace, receipt)
    )
    option = arguments.index("--intermediate-pass-file")
    arguments[option + 1] = intermediate_passphrase
    result = process_runner(
        [sys.executable, DRIVER, *arguments],
        env=environment,
        timeout=120,
    )

    assert result.status == 0, result
    assert workspace.passphrase_file.read_text().strip() not in result.stdout
    assert workspace.passphrase_file.read_text().strip() not in result.stderr
    observed = log.read_text(encoding="ascii").splitlines()
    assert "ca:root" in observed
    assert observed.count("genpkey:intermediate") == 1
    assert observed.count("req:intermediate") == 1
    assert observed.count("genpkey:root") == (1 if rollover_type == "root" else 0)
    assert observed.count("req:root") == (1 if rollover_type == "root" else 0)
    assert observed.count("pkey:root") == 1
    assert observed.count("pkey:intermediate") == 1
    assert all(
        line.endswith(":none")
        for line in observed
        if line.split(":", 1)[0] in {"x509", "verify"}
    )


@pytest.mark.parametrize("rollover_type", ("intermediate", "root"))
def test_python_prepare_success_matches_frozen_bash(
    tmp_path: Path,
    rollover_tools: RolloverTools,
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
    rollover_type: str,
) -> None:
    seed = rollover_case_factory(f"python-prepare-differential-seed-{rollover_type}")
    _rebase_seed_configs(seed)

    def prepare(root: Path, environment: Mapping[str, str]) -> None:
        workspace = _workspace(root)
        (workspace.pki / "state/rollover/journal").unlink(missing_ok=True)
        backup_environment = dict(environment)
        backup_environment["PLATFORM_TOOLS_LIB_DIR"] = os.fspath(
            REPOSITORY / "lib"
        )
        _create_backup(
            rollover_tools, workspace, backup_environment, process_runner
        )

    case_root = tmp_path / f"python-prepare-differential-{rollover_type}"
    environment = dict(isolated_environment)
    environment["PLATFORM_TOOLS_LIB_DIR"] = os.fspath(ORACLE.parent / "lib")
    if rollover_type == "root":
        trust_source = seed.private_repo / "pki/trust-consumers.yml"
        trust_source.write_text(VALID_TRUST_CONSUMERS, encoding="ascii")
        trust_source.chmod(0o600)
    arguments = _root_arguments if rollover_type == "root" else _arguments
    normalization = (
        _ROOT_PREPARATION_NORMALIZATION
        if rollover_type == "root"
        else _PREPARATION_NORMALIZATION
    )
    result = run_differential_case(
        seed.root,
        case_root,
        Path("ns/pki"),
        lambda root: (
            ORACLE,
            "prepare",
            *arguments(_workspace(root), _differential_receipt(root)),
        ),
        lambda root: (
            sys.executable,
            DRIVER,
            *arguments(_workspace(root), _differential_receipt(root)),
        ),
        environment,
        output_normalizers=(
            lambda root, value: _normalize_recovery_output(
                root,
                _CERTIFICATION_EXPIRY.sub("<CERTIFICATE-EXPIRY>", value),
                normalization,
            ),
        ),
        content_normalizers=(
            _recovery_content_normalizer(
                normalization,
                seed.root,
                case_root / "bash",
                case_root / "python",
            ),
        ),
        path_normalizers=(
            lambda value: _replace_dynamic_tokens(
                value, normalization
            ),
        ),
        runner=process_runner,
        run_options={"timeout": 120},
        bash_prepare=prepare,
        python_prepare=prepare,
    )

    result.assert_equivalent()
