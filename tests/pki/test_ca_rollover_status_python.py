import fcntl
import hashlib
import os
import shutil
import stat
import sys
import tempfile
from collections.abc import Callable, Mapping
from pathlib import Path

import pytest

from ..harness import ProcessResult
from .conftest import RolloverTools, RolloverWorkspace
from .test_ca_rollover_status import control_tree_snapshot


pytestmark = pytest.mark.pki

REPOSITORY = Path(__file__).resolve().parents[2]
ORACLE = (
    REPOSITORY
    / "tests/pki/oracles/platform-pki-ca-rollover/platform-pki-ca-rollover"
)
ORACLE_LIBRARY = ORACLE.parent / "lib/platform-pki-common.sh"
ORACLE_COMMIT = "ba9dd57214cae18f82c83dfb54b6ddce13882280"
ORACLE_SHA256 = "7e9430e6d17969d5d1779e8073b9757e08157625e16b91969991e611953b806b"
ORACLE_LIBRARY_SHA256 = "dee644be8ab6236cb368a553493f55b53a90c3aead291550f7e635c080a5494f"
DRIVER = REPOSITORY / "tests/pki/ca_rollover_status_driver.py"


def _compare(
    workspace: RolloverWorkspace,
    environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
    *arguments: str,
) -> None:
    command = ["status", "--namespace", workspace.namespace, *arguments]
    before = control_tree_snapshot(workspace.pki)
    oracle_environment = dict(environment)
    oracle_environment["PLATFORM_TOOLS_LIB_DIR"] = os.fspath(ORACLE.parent / "lib")
    oracle = process_runner(
        [ORACLE, *command], env=oracle_environment, timeout=30
    )
    assert control_tree_snapshot(workspace.pki) == before
    python = process_runner(
        [sys.executable, DRIVER, *command[1:]], env=environment, timeout=30
    )
    assert (python.status, python.stdout, python.stderr) == (
        oracle.status,
        oracle.stdout,
        oracle.stderr,
    )
    assert control_tree_snapshot(workspace.pki) == before


def _run_python(
    workspace: RolloverWorkspace,
    environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
    *,
    extra_environment: Mapping[str, str] | None = None,
) -> ProcessResult:
    effective_environment = dict(environment)
    if extra_environment is not None:
        effective_environment.update(extra_environment)
    return process_runner(
        [sys.executable, DRIVER, "--namespace", workspace.namespace],
        env=effective_environment,
        timeout=30,
    )


def _refresh_rollover_tree_manifest(
    workspace: RolloverWorkspace,
    environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> Path:
    pointer = workspace.pki / "state/active-rollover"
    transaction = next(
        line.removeprefix("transaction=")
        for line in pointer.read_text(encoding="ascii").splitlines()
        if line.startswith("transaction=")
    )
    rollover = workspace.pki / "state/rollovers" / transaction
    generated = process_runner(
        [
            "bash",
            "-c",
            'source "$1"; pki_tree_manifest "$2" tree.manifest',
            "_",
            ORACLE_LIBRARY,
            rollover,
        ],
        env=environment,
        timeout=30,
    )
    assert generated.status == 0, generated
    assert generated.stderr == ""
    tree_manifest = rollover / "tree.manifest"
    tree_manifest.write_text(generated.stdout, encoding="ascii")
    tree_manifest.chmod(0o600)
    pointer.write_text(
        f"transaction={transaction}\n"
        f"tree_manifest_sha256={hashlib.sha256(tree_manifest.read_bytes()).hexdigest()}\n",
        encoding="ascii",
    )
    return rollover / "manifest"


def test_frozen_status_oracle_matches_recorded_provenance_and_modes() -> None:
    plan = (
        REPOSITORY / "docs/plans/platform-pki-python-migration.md"
    ).read_text(encoding="utf-8")

    assert hashlib.sha256(ORACLE.read_bytes()).hexdigest() == ORACLE_SHA256
    assert (
        hashlib.sha256(ORACLE_LIBRARY.read_bytes()).hexdigest()
        == ORACLE_LIBRARY_SHA256
    )
    assert ORACLE_COMMIT in plan
    assert stat.S_IMODE(ORACLE.stat().st_mode) == 0o755
    assert stat.S_IMODE(ORACLE_LIBRARY.stat().st_mode) == 0o644


def test_python_status_recovery_matches_frozen_oracle(
    rollover_control_workspace_factory: Callable[[str], RolloverWorkspace],
    isolated_environment: Mapping[str, str],
    private_text_writer: Callable[[Path, str], None],
    process_runner: Callable[..., ProcessResult],
) -> None:
    workspace = rollover_control_workspace_factory("python-status-recovery")
    for directory in (
        workspace.namespace,
        workspace.pki,
        workspace.pki / "locks",
        workspace.pki / "state",
        workspace.pki / "state/rollover",
        workspace.pki / "state/rollovers",
        workspace.pki / "state/generation-reservations",
    ):
        directory.mkdir(mode=0o700)
    for lock in ("lifecycle", "root", "intermediate", "inventory", "export"):
        private_text_writer(workspace.pki / "locks" / lock, "")
    private_text_writer(
        workspace.pki / "state/rollover/recovery-required",
        "transaction=prepare-root-20260812-000000-2\n"
        "operation=rollover-prepare\nterminal_outcome=resumed\n",
    )
    _compare(workspace, isolated_environment, process_runner)
    _compare(workspace, isolated_environment, process_runner, "--format", "json")


def test_python_status_layouts_match_frozen_oracle(
    rollover_control_workspace_factory: Callable[[str], RolloverWorkspace],
    legacy_rollover_case_factory: Callable[[str], RolloverWorkspace],
    isolated_environment: Mapping[str, str],
    private_text_writer: Callable[[Path, str], None],
    process_runner: Callable[..., ProcessResult],
) -> None:
    empty = rollover_control_workspace_factory("python-status-empty")
    for directory in (
        empty.namespace,
        empty.pki,
        empty.pki / "locks",
        empty.pki / "state",
        empty.pki / "state/rollover",
        empty.pki / "state/rollovers",
        empty.pki / "state/generation-reservations",
    ):
        directory.mkdir(mode=0o700)
    for lock in ("lifecycle", "root", "intermediate", "inventory", "export"):
        private_text_writer(empty.pki / "locks" / lock, "")
    _compare(empty, isolated_environment, process_runner)
    _compare(empty, isolated_environment, process_runner, "--format", "json")

    legacy = legacy_rollover_case_factory("python-status-legacy")
    (legacy.pki / "state/rollover/journal").unlink(missing_ok=True)
    (legacy.pki / "state/rollovers").mkdir(mode=0o700, exist_ok=True)
    for lock in ("lifecycle", "root", "intermediate", "inventory", "export"):
        path = legacy.pki / "locks" / lock
        if not path.exists():
            private_text_writer(path, "")
    _compare(legacy, isolated_environment, process_runner)
    _compare(legacy, isolated_environment, process_runner, "--format", "json")


def test_python_status_prepared_root_matches_frozen_oracle(
    rollover_tools: RolloverTools,
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    private_text_writer: Callable[[Path, str], None],
    process_runner: Callable[..., ProcessResult],
) -> None:
    workspace = rollover_case_factory("python-status-prepared-root")
    (workspace.pki / "state/rollover/journal").unlink(missing_ok=True)
    private_text_writer(
        workspace.private_repo / "pki/trust-consumers.yml",
        "consumers:\n  managed-cluster:\n    kind: managed\n",
    )
    receipt = backup_receipt_factory(workspace)
    prepared = process_runner(
        [
            rollover_tools.rollover,
            "prepare",
            "--namespace",
            workspace.namespace,
            "--type",
            "root",
            "--backup-receipt",
            receipt,
            "--root-name",
            "Python Status G2 Root CA",
            "--intermediate-name",
            "Python Status G2-I1 Intermediate CA",
            "--org",
            "Test",
            "--country",
            "US",
            "--root-pass-file",
            workspace.passphrase_file,
            "--intermediate-pass-file",
            workspace.passphrase_file,
            "--private-repo",
            workspace.private_repo,
        ],
        env=isolated_environment,
        timeout=120,
    )
    assert prepared.status == 0, prepared

    _compare(workspace, isolated_environment, process_runner)
    _compare(workspace, isolated_environment, process_runner, "--format", "json")


def test_python_status_ready_matches_frozen_oracle(
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    isolated_environment: Mapping[str, str],
    private_text_writer: Callable[[Path, str], None],
    process_runner: Callable[..., ProcessResult],
) -> None:
    workspace = rollover_case_factory("python-status-ready")
    (workspace.pki / "state/rollover/journal").unlink(missing_ok=True)
    (workspace.pki / "state/rollovers").mkdir(mode=0o700, exist_ok=True)
    for lock in ("lifecycle", "root", "intermediate", "inventory", "export"):
        path = workspace.pki / "locks" / lock
        if not path.exists():
            private_text_writer(path, "")

    _compare(workspace, isolated_environment, process_runner)
    _compare(workspace, isolated_environment, process_runner, "--format", "json")


def test_python_status_invalid_marker_and_missing_issuer_match_frozen_oracle(
    rollover_control_workspace_factory: Callable[[str], RolloverWorkspace],
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    isolated_environment: Mapping[str, str],
    private_text_writer: Callable[[Path, str], None],
    process_runner: Callable[..., ProcessResult],
) -> None:
    marker_workspace = rollover_control_workspace_factory("python-status-marker")
    for directory in (
        marker_workspace.namespace,
        marker_workspace.pki,
        marker_workspace.pki / "locks",
        marker_workspace.pki / "state",
        marker_workspace.pki / "state/rollover",
        marker_workspace.pki / "state/rollovers",
        marker_workspace.pki / "state/generation-reservations",
    ):
        directory.mkdir(mode=0o700)
    for lock in ("lifecycle", "root", "intermediate", "inventory", "export"):
        private_text_writer(marker_workspace.pki / "locks" / lock, "")
    private_text_writer(
        marker_workspace.pki / "state/rollover/recovery-required",
        "transaction=prepare-root-20260812-000000-1\n"
        "operation=rollover-prepare\nterminal_outcome=invalid\n",
    )
    marker_result = _run_python(
        marker_workspace, isolated_environment, process_runner
    )
    assert marker_result.status == 1
    assert marker_result.stdout == ""
    assert marker_result.stderr == (
        "[ERROR] PKI recovery marker has invalid terminal preparation state\n"
    )

    issuer_workspace = rollover_case_factory("python-status-missing-issuer")
    (issuer_workspace.pki / "state/rollover/journal").unlink(missing_ok=True)
    (issuer_workspace.pki / "state/rollovers").mkdir(mode=0o700, exist_ok=True)
    for lock in ("lifecycle", "root", "intermediate", "inventory", "export"):
        path = issuer_workspace.pki / "locks" / lock
        if not path.exists():
            private_text_writer(path, "")
    (issuer_workspace.pki / "services/app/issuer").unlink()
    _compare(
        issuer_workspace,
        isolated_environment,
        process_runner,
        "--format",
        "json",
    )


@pytest.mark.parametrize(
    "lock_name", ("lifecycle", "root", "intermediate", "inventory", "export")
)
def test_python_status_lock_contention_matches_frozen_oracle(
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    isolated_environment: Mapping[str, str],
    private_text_writer: Callable[[Path, str], None],
    process_runner: Callable[..., ProcessResult],
    lock_name: str,
) -> None:
    workspace = rollover_case_factory(f"python-status-lock-{lock_name}")
    (workspace.pki / "state/rollover/journal").unlink(missing_ok=True)
    (workspace.pki / "state/rollovers").mkdir(mode=0o700, exist_ok=True)
    for name in ("lifecycle", "root", "intermediate", "inventory", "export"):
        path = workspace.pki / "locks" / name
        if not path.exists():
            private_text_writer(path, "")
    with (workspace.pki / "locks" / lock_name).open("r+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        _compare(workspace, isolated_environment, process_runner)


@pytest.mark.parametrize(
    ("record", "content"),
    (
        pytest.param(
            "state/rollover/journal",
            "operation=rollover-prepare\ntransaction=bad/value\n"
            "phase=bad/value\nterminal_outcome=none\n",
            id="sanitized-preparation-journal",
        ),
        pytest.param(
            "state/rollover/journal",
            "operation=rollover-prepare\ntransaction=prepare-root-20260812-000000-1\n"
            "phase=prepared\nterminal_outcome=invalid\n",
            id="invalid-preparation-outcome",
        ),
        pytest.param(
            "state/rollover/journal",
            "operation\n",
            id="malformed-journal-record",
        ),
    ),
)
def test_python_status_rejects_malformed_recovery_shapes_and_scalars(
    rollover_control_workspace_factory: Callable[[str], RolloverWorkspace],
    isolated_environment: Mapping[str, str],
    private_text_writer: Callable[[Path, str], None],
    process_runner: Callable[..., ProcessResult],
    record: str,
    content: str,
) -> None:
    case = record.replace("/", "-") + "-" + hashlib.sha256(content.encode()).hexdigest()[:8]
    workspace = rollover_control_workspace_factory(f"python-status-{case}")
    for directory in (
        workspace.namespace,
        workspace.pki,
        workspace.pki / "locks",
        workspace.pki / "state",
        workspace.pki / "state/rollover",
        workspace.pki / "state/rollovers",
        workspace.pki / "state/generation-reservations",
    ):
        directory.mkdir(mode=0o700)
    for lock in ("lifecycle", "root", "intermediate", "inventory", "export"):
        private_text_writer(workspace.pki / "locks" / lock, "")
    private_text_writer(workspace.pki / record, content)

    for output_format in ("text", "json"):
        result = process_runner(
            [
                sys.executable,
                DRIVER,
                "--namespace",
                workspace.namespace,
                "--format",
                output_format,
            ],
            env=isolated_environment,
            timeout=30,
        )
        assert result.status == 1
        assert result.stdout == ""
        assert result.stderr.startswith("[ERROR] PKI recovery ")


@pytest.mark.parametrize("hostile_kind", ("replacement", "symlink", "hardlink"))
def test_python_status_rejects_unsafe_active_certificate_without_output(
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    isolated_environment: Mapping[str, str],
    private_text_writer: Callable[[Path, str], None],
    process_runner: Callable[..., ProcessResult],
    tmp_path: Path,
    hostile_kind: str,
) -> None:
    workspace = rollover_case_factory(f"python-status-certificate-{hostile_kind}")
    (workspace.pki / "state/rollover/journal").unlink(missing_ok=True)
    (workspace.pki / "state/rollovers").mkdir(mode=0o700, exist_ok=True)
    for name in ("lifecycle", "root", "intermediate", "inventory", "export"):
        path = workspace.pki / "locks" / name
        if not path.exists():
            private_text_writer(path, "")
    certificate = workspace.pki / "authorities/roots/g1/certs/root-ca.crt"
    external = tmp_path / f"root-ca-{hostile_kind}.crt"
    if hostile_kind == "replacement":
        shutil.copyfile(
            workspace.pki
            / "authorities/intermediates/g1-i1/certs/intermediate-ca.crt",
            external,
        )
        shutil.copystat(certificate, external)
        os.replace(external, certificate)
    elif hostile_kind == "symlink":
        shutil.copyfile(certificate, external)
        certificate.unlink()
        certificate.symlink_to(external)
    else:
        os.link(certificate, external)

    before = control_tree_snapshot(workspace.pki)
    result = _run_python(
        workspace, isolated_environment, process_runner
    )

    assert result.status == 1
    assert result.stdout == ""
    if hostile_kind in ("symlink", "hardlink"):
        assert result.stderr.startswith("[ERROR] Required file is missing: ")
    else:
        assert result.stderr.endswith(
            "[ERROR] Active intermediate does not verify against its recorded root\n"
        )
    assert control_tree_snapshot(workspace.pki) == before


def test_python_status_rejects_certificate_path_replacement_after_open(
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    isolated_environment: Mapping[str, str],
    private_text_writer: Callable[[Path, str], None],
    process_runner: Callable[..., ProcessResult],
    tmp_path: Path,
) -> None:
    workspace = rollover_case_factory("python-status-certificate-race")
    (workspace.pki / "state/rollover/journal").unlink(missing_ok=True)
    (workspace.pki / "state/rollovers").mkdir(mode=0o700, exist_ok=True)
    for name in ("lifecycle", "root", "intermediate", "inventory", "export"):
        path = workspace.pki / "locks" / name
        if not path.exists():
            private_text_writer(path, "")
    certificate = workspace.pki / "authorities/roots/g1/certs/root-ca.crt"
    replacement = tmp_path / "replacement-root-ca.crt"
    shutil.copyfile(certificate, replacement)

    result = _run_python(
        workspace,
        isolated_environment,
        process_runner,
        extra_environment={
            "PLATFORM_PKI_STATUS_RACE_TARGET": os.fspath(certificate),
            "PLATFORM_PKI_STATUS_RACE_REPLACEMENT": os.fspath(replacement),
        },
    )

    assert result.status == 1
    assert result.stdout == ""
    assert result.stderr == (
        "[ERROR] Certificate identity changed before status output\n"
    )


def test_python_status_prepared_matches_frozen_oracle(
    rollover_tools: RolloverTools,
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> None:
    workspace = rollover_case_factory("python-status-prepared")
    (workspace.pki / "state/rollover/journal").unlink(missing_ok=True)
    receipt = backup_receipt_factory(workspace)
    prepared = process_runner(
        [
            rollover_tools.rollover,
            "prepare",
            "--namespace",
            workspace.namespace,
            "--type",
            "intermediate",
            "--backup-receipt",
            receipt,
            "--intermediate-name",
            "Python Status G1-I2 Candidate CA",
            "--org",
            "Test",
            "--country",
            "US",
            "--root-pass-file",
            workspace.passphrase_file,
            "--intermediate-pass-file",
            workspace.passphrase_file,
        ],
        env=isolated_environment,
        timeout=120,
    )
    assert prepared.status == 0, prepared

    _compare(workspace, isolated_environment, process_runner)
    _compare(workspace, isolated_environment, process_runner, "--format", "json")
    manifest = _refresh_rollover_tree_manifest(
        workspace, isolated_environment, process_runner
    )
    original_manifest = manifest.read_text(encoding="ascii")
    malformed_manifests = (
        original_manifest.replace("phase=prepared\n", "phase=invalid\n"),
        "\n".join(
            line
            for line in original_manifest.splitlines()
            if not line.startswith("created_at=")
        )
        + "\n",
    )
    for malformed in malformed_manifests:
        manifest.write_text(malformed, encoding="ascii")
        _refresh_rollover_tree_manifest(workspace, isolated_environment, process_runner)
        _compare(workspace, isolated_environment, process_runner)
    manifest.write_text(original_manifest, encoding="ascii")
    _refresh_rollover_tree_manifest(workspace, isolated_environment, process_runner)
    candidate = workspace.pki / "authorities/intermediates/g1-i2/openssl.cnf"
    candidate.write_bytes(candidate.read_bytes() + b"# status tamper\n")
    _compare(workspace, isolated_environment, process_runner)


def test_python_status_rejects_coherent_unrelated_candidate_certificate(
    rollover_tools: RolloverTools,
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> None:
    workspace = rollover_case_factory("python-status-unrelated-candidate")
    (workspace.pki / "state/rollover/journal").unlink(missing_ok=True)
    receipt = backup_receipt_factory(workspace)
    prepared = process_runner(
        [
            rollover_tools.rollover,
            "prepare",
            "--namespace",
            workspace.namespace,
            "--type",
            "intermediate",
            "--backup-receipt",
            receipt,
            "--intermediate-name",
            "Python Status G1-I2 Candidate CA",
            "--org",
            "Test",
            "--country",
            "US",
            "--root-pass-file",
            workspace.passphrase_file,
            "--intermediate-pass-file",
            workspace.passphrase_file,
        ],
        env=isolated_environment,
        timeout=120,
    )
    assert prepared.status == 0, prepared

    candidate = workspace.pki / "authorities/intermediates/g1-i2/certs/intermediate-ca.crt"
    with tempfile.TemporaryDirectory(dir=workspace.root) as temporary:
        temporary_path = Path(temporary)
        unrelated_key = temporary_path / "unrelated.key"
        unrelated = temporary_path / "unrelated.crt"
        created = process_runner(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-subj",
                "/CN=Unrelated Candidate Intermediate",
                "-keyout",
                unrelated_key,
                "-out",
                unrelated,
                "-days",
                "365",
            ],
            env=isolated_environment,
            timeout=30,
        )
        assert created.status == 0, created
        shutil.copyfile(unrelated, candidate)
    pointer = workspace.pki / "state/active-rollover"
    transaction = next(
        line.removeprefix("transaction=")
        for line in pointer.read_text(encoding="ascii").splitlines()
        if line.startswith("transaction=")
    )
    rollover = workspace.pki / "state/rollovers" / transaction
    candidate_tree = rollover / "candidate-intermediate-tree.manifest"
    generated = process_runner(
        [
            "bash",
            "-c",
            'source "$1"; pki_tree_manifest "$2"',
            "_",
            ORACLE_LIBRARY,
            candidate.parent.parent,
        ],
        env=isolated_environment,
        timeout=30,
    )
    assert generated.status == 0, generated
    candidate_tree.write_text(generated.stdout, encoding="ascii")
    candidate_tree.chmod(0o600)
    manifest = rollover / "manifest"
    fingerprint, expiry = _certificate_values(
        candidate, isolated_environment, process_runner
    )
    values = manifest.read_text(encoding="ascii")
    values = _replace_record_value(
        values, "candidate_intermediate_fingerprint", fingerprint
    )
    values = _replace_record_value(values, "candidate_intermediate_expiry", expiry)
    values = _replace_record_value(
        values,
        "candidate_intermediate_tree_sha256",
        hashlib.sha256(candidate_tree.read_bytes()).hexdigest(),
    )
    manifest.write_text(values, encoding="ascii")
    _refresh_rollover_tree_manifest(workspace, isolated_environment, process_runner)

    result = _run_python(workspace, isolated_environment, process_runner)

    assert result.status == 1
    assert result.stdout == ""
    assert result.stderr.endswith(
        "[ERROR] Prepared candidate intermediate does not verify against its recorded root\n"
    )


def _replace_record_value(content: str, field: str, value: str) -> str:
    return "".join(
        f"{field}={value}\n" if line.startswith(f"{field}=") else line
        for line in content.splitlines(keepends=True)
    )


def _certificate_values(
    certificate: Path,
    environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> tuple[str, str]:
    fingerprint = process_runner(
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
    enddate = process_runner(
        ["openssl", "x509", "-in", certificate, "-noout", "-enddate"],
        env=environment,
        timeout=30,
    )
    assert fingerprint.status == 0 and enddate.status == 0
    expiry = process_runner(
        [
            "date",
            "-u",
            "-d",
            enddate.stdout.strip().removeprefix("notAfter="),
            "+%Y-%m-%dT%H:%M:%SZ",
        ],
        env=environment,
        timeout=30,
    )
    assert expiry.status == 0
    return (
        fingerprint.stdout.strip().partition("=")[2].replace(":", ""),
        expiry.stdout.strip(),
    )


@pytest.mark.parametrize(
    ("target", "mode"),
    (
        ("state/active-issuer", "replace"),
        ("services/app/issuer", "remove"),
        ("state/active-rollover", "create"),
    ),
)
def test_python_status_rejects_status_record_and_absence_races(
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    isolated_environment: Mapping[str, str],
    private_text_writer: Callable[[Path, str], None],
    process_runner: Callable[..., ProcessResult],
    tmp_path: Path,
    target: str,
    mode: str,
) -> None:
    workspace = rollover_case_factory(f"python-status-record-race-{mode}")
    (workspace.pki / "state/rollover/journal").unlink(missing_ok=True)
    (workspace.pki / "state/rollovers").mkdir(mode=0o700, exist_ok=True)
    for name in ("lifecycle", "root", "intermediate", "inventory", "export"):
        lock = workspace.pki / "locks" / name
        if not lock.exists():
            private_text_writer(lock, "")
    race_target = workspace.pki / target
    extra = {
        "PLATFORM_PKI_STATUS_RACE_TARGET": os.fspath(race_target),
        "PLATFORM_PKI_STATUS_RACE_MODE": mode,
    }
    if mode == "replace":
        replacement = tmp_path / "replacement-record"
        shutil.copyfile(race_target, replacement)
        extra["PLATFORM_PKI_STATUS_RACE_REPLACEMENT"] = os.fspath(replacement)

    result = _run_python(
        workspace,
        isolated_environment,
        process_runner,
        extra_environment=extra,
    )

    assert result.status == 1
    assert result.stdout == ""
    assert result.stderr == "[ERROR] Status record identity changed before output\n"
