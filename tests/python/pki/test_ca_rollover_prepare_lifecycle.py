import json
import re
import stat
from collections.abc import Callable, Mapping
from hashlib import sha256
from pathlib import Path

import pytest

from ..harness import ProcessResult
from .conftest import RolloverTools, RolloverWorkspace


pytestmark = pytest.mark.pki

TRUST_CONSUMERS = """consumers:
  managed-cluster:
    kind: managed
  firewall.manual:
    kind: manual
"""


def _run(
    command: list[str | Path],
    environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
    *,
    timeout: int = 120,
) -> ProcessResult:
    return process_runner(command, env=environment, timeout=timeout)


def _transaction(workspace: RolloverWorkspace) -> tuple[str, Path]:
    pointer = dict(
        line.split("=", 1)
        for line in (workspace.pki / "state/active-rollover").read_text().splitlines()
    )
    transaction = pointer["transaction"]
    assert re.fullmatch(
        r"prepare-(?:root|intermediate)-[0-9]{8}-[0-9]{6}-[0-9]+",
        transaction,
    )
    return transaction, workspace.pki / "state/rollovers" / transaction


def _assert_manifest_complete_and_redacted(authority: Path, manifest: Path) -> None:
    content = manifest.read_text()
    rows: dict[str, tuple[str, str]] = {}
    for line in content.splitlines():
        fields = line.split("|")
        assert len(fields) == 4
        object_type, relative, identity, digest = fields
        relative_path = Path(relative)
        assert relative
        assert not relative_path.is_absolute()
        assert relative_path.parts
        assert all(part not in {"", ".", ".."} for part in relative_path.parts)
        assert relative_path.as_posix() == relative
        assert relative not in rows
        assert object_type in {"directory", "regular file", "regular empty file"}
        if object_type == "directory":
            assert re.fullmatch(r"[0-9]+:[0-9]+:[0-9]+:[0-7]+:directory", identity)
        else:
            assert re.fullmatch(
                r"[0-9]+:[0-9]+:[0-9]+:[0-7]+:[0-9]+:[0-9]+:.+:.+:"
                + re.escape(object_type),
                identity,
            )
        rows[relative] = (object_type, digest)

    expected: dict[str, tuple[str, Path]] = {}
    for path in sorted(authority.rglob("*")):
        metadata = path.lstat()
        relative = path.relative_to(authority).as_posix()
        if stat.S_ISDIR(metadata.st_mode):
            object_type = "directory"
        else:
            assert stat.S_ISREG(metadata.st_mode)
            object_type = (
                "regular empty file" if metadata.st_size == 0 else "regular file"
            )
        expected[relative] = (object_type, path)

    assert set(rows) == set(expected)
    for relative, (object_type, path) in expected.items():
        manifest_type, digest = rows[relative]
        assert manifest_type == object_type
        if object_type == "directory":
            assert digest == "-"
            continue

        sensitive = (
            "private" in Path(relative).parts
            or relative.endswith(".key")
            or "passphrase" in relative
        )
        if sensitive:
            assert digest == "secret"
        else:
            assert re.fullmatch(r"[0-9a-f]{64}", digest)
            assert digest == sha256(path.read_bytes()).hexdigest()

    assert "pytest-rollover-passphrase" not in content


def _assert_published_config(
    workspace: RolloverWorkspace,
    authority: Path,
    transaction: str,
) -> None:
    content = (authority / "openssl.cnf").read_text()
    assert re.findall(r"^dir = (.+)$", content, re.MULTILINE) == [str(authority)]
    absolute_values = [
        value.strip()
        for line in content.splitlines()
        for _, separator, value in (line.partition("="),)
        if separator and value.strip().startswith("/")
    ]
    assert absolute_values == [str(authority)]
    transaction_stage = (
        workspace.pki / "state/rollover" / transaction / "stage"
    )
    assert str(transaction_stage) not in content
    assert str(workspace.pki / "state/rollover") not in content


def _certificate_observables(
    certificate: Path,
    environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> tuple[str, str]:
    fingerprint = _run(
        ["openssl", "x509", "-in", certificate, "-noout", "-fingerprint", "-sha256"],
        environment,
        process_runner,
        timeout=10,
    )
    assert fingerprint.status == 0
    assert fingerprint.stderr == ""
    fingerprint_value = fingerprint.stdout.strip().partition("=")[2].replace(":", "")
    assert re.fullmatch(r"[0-9A-F]{64}", fingerprint_value)

    enddate = _run(
        ["openssl", "x509", "-in", certificate, "-noout", "-enddate"],
        environment,
        process_runner,
        timeout=10,
    )
    assert enddate.status == 0
    assert enddate.stderr == ""
    expiry = _run(
        [
            "date",
            "-u",
            "-d",
            enddate.stdout.strip().removeprefix("notAfter="),
            "+%Y-%m-%dT%H:%M:%SZ",
        ],
        environment,
        process_runner,
        timeout=10,
    )
    assert expiry.status == 0
    assert expiry.stderr == ""
    assert re.fullmatch(
        r"[0-9]{4}(?:-[0-9]{2}){2}T[0-9]{2}(?::[0-9]{2}){2}Z",
        expiry.stdout.strip(),
    )
    return fingerprint_value, expiry.stdout.strip()


def _assert_prepare_stderr(
    stderr: str,
    workspace: RolloverWorkspace,
    rollover_type: str,
    common_name: str,
) -> None:
    assert re.fullmatch(
        rf"Using configuration from {re.escape(str(workspace.pki))}/state/rollover/"
        rf"prepare-{rollover_type}-[0-9]{{8}}-[0-9]{{6}}-[0-9]+/stage/root/"
        r"openssl\.cnf\n"
        r"Check that the request matches the signature\n"
        r"Signature ok\n"
        r"The Subject's Distinguished Name is as follows\n"
        r"countryName           :PRINTABLE:'US'\n"
        r"organizationName      :ASN\.1 12:'Test'\n"
        rf"commonName            :ASN\.1 12:'{re.escape(common_name)}'\n"
        r"Certificate is to be certified until .+ GMT \(1825 days\)\n\n"
        r"Write out database with 1 new entries\n"
        r"Database updated\n",
        stderr,
    )


def _metadata_tree(root: Path) -> tuple[tuple[str, int, int, int, int], ...]:
    return tuple(
        (
            path.relative_to(root).as_posix(),
            stat.S_IFMT(metadata.st_mode),
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
        )
        for path in (root, *sorted(root.rglob("*")))
        for metadata in (path.lstat(),)
    )


def _state_snapshot(root: Path) -> tuple[tuple[str, int, int, int, bytes], ...]:
    return tuple(
        (
            path.relative_to(root).as_posix(),
            stat.S_IFMT(metadata.st_mode),
            metadata.st_size,
            metadata.st_mtime_ns,
            path.read_bytes() if stat.S_ISREG(metadata.st_mode) else b"",
        )
        for path in (root, *sorted(root.rglob("*")))
        for metadata in (path.lstat(),)
    )


def _rebase_authority_config(authority: Path) -> None:
    config = authority / "openssl.cnf"
    content = config.read_text()
    match = re.search(r"^dir = (.+)$", content, re.MULTILINE)
    assert match is not None
    config.write_text(content.replace(match.group(1), str(authority)))


def test_intermediate_prepare_publication(
    rollover_tools: RolloverTools,
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> None:
    workspace = rollover_case_factory("intermediate-prepare-publication")
    _rebase_authority_config(
        workspace.pki / "authorities/intermediates/g1-i1"
    )
    receipt = backup_receipt_factory(workspace)
    active_before = (workspace.pki / "state/active-issuer").read_text()
    historical_manifest = (
        workspace.pki
        / "state/rollover/.prepare-intermediate-20000101-000000-1.transaction-tree.1"
    )
    historical_manifest.write_text("reviewed historical residue\n")
    historical_manifest.chmod(0o600)
    historical_metadata = historical_manifest.stat()

    result = _run(
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
            "Test G1-I2 Intermediate CA",
            "--org",
            "Test",
            "--country",
            "US",
            "--root-pass-file",
            workspace.passphrase_file,
            "--intermediate-pass-file",
            workspace.passphrase_file,
        ],
        isolated_environment,
        process_runner,
    )

    assert result.status == 0
    _assert_prepare_stderr(
        result.stderr,
        workspace,
        "intermediate",
        "Test G1-I2 Intermediate CA",
    )
    assert re.fullmatch(
        r"\[OK\] Prepared intermediate rollover transaction "
        r"prepare-intermediate-[0-9]{8}-[0-9]{6}-[0-9]+ "
        r"with candidate g1/g1-i2\n",
        result.stdout,
    )
    assert (workspace.pki / "state/active-issuer").read_text() == active_before
    candidate = workspace.pki / "authorities/intermediates/g1-i2"
    assert candidate.is_dir() and not candidate.is_symlink()
    transaction, state = _transaction(workspace)
    assert not tuple(
        (workspace.pki / "state/rollover").glob(
            f".{transaction}.transaction-tree.*"
        )
    )
    assert historical_manifest.read_text() == "reviewed historical residue\n"
    current_historical_metadata = historical_manifest.stat()
    assert (
        current_historical_metadata.st_dev,
        current_historical_metadata.st_ino,
        stat.S_IMODE(current_historical_metadata.st_mode),
        current_historical_metadata.st_nlink,
        current_historical_metadata.st_size,
        current_historical_metadata.st_mtime_ns,
    ) == (
        historical_metadata.st_dev,
        historical_metadata.st_ino,
        stat.S_IMODE(historical_metadata.st_mode),
        historical_metadata.st_nlink,
        historical_metadata.st_size,
        historical_metadata.st_mtime_ns,
    )
    _assert_manifest_complete_and_redacted(
        candidate,
        state / "candidate-intermediate-tree.manifest",
    )
    _assert_published_config(workspace, candidate, transaction)

    issue = _run(
        [
            rollover_tools.issue,
            "next",
            "--namespace",
            workspace.namespace,
            "--intermediate-pass-file",
            workspace.passphrase_file,
        ],
        isolated_environment,
        process_runner,
    )
    certificate = workspace.pki / "services/next/certs/tls.crt"
    assert issue.status == 0
    assert re.fullmatch(
        rf"Using configuration from {re.escape(str(workspace.pki))}/authorities/"
        r"intermediates/g1-i1/\.platform-pki-service-issue\.[A-Za-z0-9]+/"
        r"intermediate-ca/openssl\.cnf\n"
        r"Check that the request matches the signature\n"
        r"Signature ok\n"
        r"The Subject's Distinguished Name is as follows\n"
        r"commonName            :ASN\.1 12:'next\.example\.internal'\n"
        r"Certificate is to be certified until .+ GMT \(397 days\)\n\n"
        r"Write out database with 1 new entries\n"
        r"Database updated\n",
        issue.stderr,
    )
    assert issue.stdout == (
        "[OK] Verified service certificate: next\n"
        f"[OK] Issued service certificate: {certificate}\n"
    )
    assert (workspace.pki / "services/next/issuer").read_text() == active_before
    verify = _run(
        [
            "openssl",
            "verify",
            "-CAfile",
            workspace.pki / "authorities/roots/g1/certs/root-ca.crt",
            "-untrusted",
            workspace.pki
            / "authorities/intermediates/g1-i1/certs/intermediate-ca.crt",
            certificate,
        ],
        isolated_environment,
        process_runner,
        timeout=10,
    )
    assert verify.status == 0
    assert verify.stdout == f"{certificate}: OK\n"
    assert verify.stderr == ""

    status = _run(
        [
            rollover_tools.rollover,
            "status",
            "--namespace",
            workspace.namespace,
            "--format",
            "json",
        ],
        isolated_environment,
        process_runner,
    )
    assert status.status == 1
    assert status.stderr == ""
    active_root = workspace.pki / "authorities/roots/g1/certs/root-ca.crt"
    active_intermediate = (
        workspace.pki
        / "authorities/intermediates/g1-i1/certs/intermediate-ca.crt"
    )
    active_root_observables = _certificate_observables(
        active_root, isolated_environment, process_runner
    )
    active_intermediate_observables = _certificate_observables(
        active_intermediate, isolated_environment, process_runner
    )
    candidate_intermediate_observables = _certificate_observables(
        candidate / "certs/intermediate-ca.crt",
        isolated_environment,
        process_runner,
    )
    assert json.loads(status.stdout) == {
        "schema": 1,
        "status": "prepared",
        "recovery_required": False,
        "transaction": transaction,
        "type": "intermediate",
        "phase": "prepared",
        "active": {
            "root": {
                "generation": "g1",
                "fingerprint_sha256": active_root_observables[0],
                "expires_at": active_root_observables[1],
            },
            "intermediate": {
                "generation": "g1-i1",
                "fingerprint_sha256": active_intermediate_observables[0],
                "expires_at": active_intermediate_observables[1],
            },
        },
        "candidate": {
            "root": {
                "generation": "g1",
                "fingerprint_sha256": active_root_observables[0],
                "expires_at": active_root_observables[1],
            },
            "intermediate": {
                "generation": "g1-i2",
                "fingerprint_sha256": candidate_intermediate_observables[0],
                "expires_at": candidate_intermediate_observables[1],
            },
        },
        "retired": [],
        "trust_bundle_sha256": "none",
        "trust_snapshot_sha256": "none",
        "services_on_old_issuer": ["app", "next"],
        "required_action": "immutable-export-evidence",
    }


def test_overlapping_active_rollover(
    rollover_tools: RolloverTools,
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> None:
    workspace = rollover_case_factory("overlapping-active-rollover")
    receipt = backup_receipt_factory(workspace)
    base_command: list[str | Path] = [
        rollover_tools.rollover,
        "prepare",
        "--namespace",
        workspace.namespace,
        "--type",
        "intermediate",
        "--backup-receipt",
        receipt,
        "--intermediate-name",
        "Test G1-I2 Intermediate CA",
        "--org",
        "Test",
        "--country",
        "US",
        "--root-pass-file",
        workspace.passphrase_file,
        "--intermediate-pass-file",
        workspace.passphrase_file,
    ]
    prepared = _run(base_command, isolated_environment, process_runner)
    assert prepared.status == 0
    _assert_prepare_stderr(
        prepared.stderr,
        workspace,
        "intermediate",
        "Test G1-I2 Intermediate CA",
    )

    active_before = (workspace.pki / "state/active-issuer").read_bytes()
    state_before = _state_snapshot(workspace.pki / "state")
    authorities_before = _metadata_tree(workspace.pki / "authorities")
    overlap_command = base_command.copy()
    overlap_command[overlap_command.index("Test G1-I2 Intermediate CA")] = (
        "Test G1-I3 Intermediate CA"
    )

    overlap = _run(overlap_command, isolated_environment, process_runner)

    assert overlap.status == 1
    assert overlap.stdout == ""
    assert overlap.stderr == "[ERROR] An active rollover already exists\n"
    assert (workspace.pki / "state/active-issuer").read_bytes() == active_before
    assert _state_snapshot(workspace.pki / "state") == state_before
    assert _metadata_tree(workspace.pki / "authorities") == authorities_before
    assert not (workspace.pki / "authorities/intermediates/g1-i3").exists()


def test_root_prepare_publication(
    rollover_tools: RolloverTools,
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    private_text_writer: Callable[[Path, str], None],
    process_runner: Callable[..., ProcessResult],
) -> None:
    workspace = rollover_case_factory("root-prepare-publication")
    trust_source = workspace.private_repo / "pki/trust-consumers.yml"
    private_text_writer(trust_source, TRUST_CONSUMERS)
    receipt = backup_receipt_factory(workspace)
    active_before = (workspace.pki / "state/active-issuer").read_text()

    result = _run(
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
            "Test G2 Root CA",
            "--intermediate-name",
            "Test G2-I1 Intermediate CA",
            "--org",
            "Test",
            "--country",
            "US",
            "--root-days",
            "3650",
            "--intermediate-days",
            "1825",
            "--root-pass-file",
            workspace.passphrase_file,
            "--intermediate-pass-file",
            workspace.passphrase_file,
            "--private-repo",
            workspace.private_repo,
        ],
        isolated_environment,
        process_runner,
    )

    assert result.status == 0
    _assert_prepare_stderr(
        result.stderr, workspace, "root", "Test G2-I1 Intermediate CA"
    )
    assert re.fullmatch(
        r"\[OK\] Prepared root rollover transaction "
        r"prepare-root-[0-9]{8}-[0-9]{6}-[0-9]+ "
        r"with candidate g2/g2-i1\n",
        result.stdout,
    )
    assert (workspace.pki / "state/active-issuer").read_text() == active_before
    root = workspace.pki / "authorities/roots/g2"
    intermediate = workspace.pki / "authorities/intermediates/g2-i1"
    assert root.is_dir() and not root.is_symlink()
    assert intermediate.is_dir() and not intermediate.is_symlink()
    candidate_root = root / "certs/root-ca.crt"
    transaction, state = _transaction(workspace)
    assert not tuple(
        (workspace.pki / "state/rollover").glob(
            f".{transaction}.transaction-tree.*"
        )
    )
    _assert_manifest_complete_and_redacted(
        root, state / "candidate-root-tree.manifest"
    )
    _assert_manifest_complete_and_redacted(
        intermediate,
        state / "candidate-intermediate-tree.manifest",
    )
    _assert_published_config(workspace, root, transaction)
    _assert_published_config(workspace, intermediate, transaction)
    assert (state / "trust-consumers.yml").read_bytes() == trust_source.read_bytes()

    verify = _run(
        [
            "openssl",
            "verify",
            "-CAfile",
            candidate_root,
            intermediate / "certs/intermediate-ca.crt",
        ],
        isolated_environment,
        process_runner,
        timeout=10,
    )
    assert verify.status == 0
    assert verify.stdout == f"{intermediate / 'certs/intermediate-ca.crt'}: OK\n"
    assert verify.stderr == ""

    valid_signature = _run(
        [
            "openssl",
            "verify",
            "-check_ss_sig",
            "-CAfile",
            candidate_root,
            candidate_root,
        ],
        isolated_environment,
        process_runner,
        timeout=10,
    )
    assert valid_signature.status == 0
    assert valid_signature.stdout == f"{candidate_root}: OK\n"
    assert valid_signature.stderr == ""

    corrupted_root = workspace.root / "bad-g2-self-signature.crt"
    corruption = _run(
        [
            "openssl",
            "x509",
            "-in",
            candidate_root,
            "-badsig",
            "-out",
            corrupted_root,
        ],
        isolated_environment,
        process_runner,
        timeout=10,
    )
    assert corruption.status == 0
    assert corruption.stdout == corruption.stderr == ""
    assert corrupted_root.is_file() and not corrupted_root.is_symlink()

    parseable = _run(
        ["openssl", "x509", "-in", corrupted_root, "-noout"],
        isolated_environment,
        process_runner,
        timeout=10,
    )
    assert parseable.status == 0
    assert parseable.stdout == parseable.stderr == ""

    invalid_signature = _run(
        [
            "openssl",
            "verify",
            "-check_ss_sig",
            "-CAfile",
            corrupted_root,
            corrupted_root,
        ],
        isolated_environment,
        process_runner,
        timeout=10,
    )
    assert invalid_signature.status != 0
    assert "certificate signature failure" in invalid_signature.stderr

    common_library = (
        Path(__file__).resolve().parents[3] / "lib/platform-pki-common.sh"
    )
    application_validation = _run(
        [
            "bash",
            "-c",
            'source "$1"; pki_require_ca_self_signature "$2" "Candidate root"',
            "_",
            common_library,
            corrupted_root,
        ],
        isolated_environment,
        process_runner,
        timeout=10,
    )
    assert application_validation.status == 1
    assert application_validation.stdout == ""
    assert application_validation.stderr.endswith(
        "[ERROR] Candidate root self-signature is invalid\n"
    )

    status = _run(
        [
            rollover_tools.rollover,
            "status",
            "--namespace",
            workspace.namespace,
            "--format",
            "json",
        ],
        isolated_environment,
        process_runner,
    )
    assert status.status == 1
    assert status.stderr == ""
    active_root = workspace.pki / "authorities/roots/g1/certs/root-ca.crt"
    active_intermediate = (
        workspace.pki
        / "authorities/intermediates/g1-i1/certs/intermediate-ca.crt"
    )
    active_root_observables = _certificate_observables(
        active_root, isolated_environment, process_runner
    )
    active_intermediate_observables = _certificate_observables(
        active_intermediate, isolated_environment, process_runner
    )
    candidate_root_observables = _certificate_observables(
        candidate_root, isolated_environment, process_runner
    )
    candidate_intermediate_observables = _certificate_observables(
        intermediate / "certs/intermediate-ca.crt",
        isolated_environment,
        process_runner,
    )
    trust_bundle_sha256 = sha256(
        active_root.read_bytes() + candidate_root.read_bytes()
    ).hexdigest()
    assert json.loads(status.stdout) == {
        "schema": 1,
        "status": "prepared",
        "recovery_required": False,
        "transaction": transaction,
        "type": "root",
        "phase": "prepared",
        "active": {
            "root": {
                "generation": "g1",
                "fingerprint_sha256": active_root_observables[0],
                "expires_at": active_root_observables[1],
            },
            "intermediate": {
                "generation": "g1-i1",
                "fingerprint_sha256": active_intermediate_observables[0],
                "expires_at": active_intermediate_observables[1],
            },
        },
        "candidate": {
            "root": {
                "generation": "g2",
                "fingerprint_sha256": candidate_root_observables[0],
                "expires_at": candidate_root_observables[1],
            },
            "intermediate": {
                "generation": "g2-i1",
                "fingerprint_sha256": candidate_intermediate_observables[0],
                "expires_at": candidate_intermediate_observables[1],
            },
        },
        "retired": [],
        "trust_bundle_sha256": trust_bundle_sha256,
        "trust_snapshot_sha256": sha256(TRUST_CONSUMERS.encode()).hexdigest(),
        "services_on_old_issuer": ["app"],
        "required_action": "immutable-export-evidence",
    }
