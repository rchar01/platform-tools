from __future__ import annotations

import fcntl
import hashlib
import json
import os
import shutil
import stat
import time
from pathlib import Path

import pytest

from ..harness import ProcessResult
from .migration_harness import run_differential_case
from .support import BIN, REPOSITORY, assert_result, digest, environment, write_private
from .test_csr_signing import CsrWorkspace, csr_workspace, tree_snapshot


pytestmark = pytest.mark.pki
EXPORT = BIN / "platform-pki-certificate-export"
UNIFIED = BIN / "platform-pki"
ORACLE_ROOT = REPOSITORY / "tests/pki/oracles/platform-pki-certificate-export"
ORACLE = ORACLE_ROOT / "platform-pki-certificate-export"
ORACLE_LIB = ORACLE_ROOT / "lib"
ORACLE_COMMIT = "24db7d54ca5c113fe763d4007c5dfef507dc23a6"
ORACLE_HASHES = {
    "platform-pki-certificate-export": "21c73b92d8568a74e8b75f554831060309c4f998d4230d28b019d72c3e1f85fa",
    "lib/platform-pki-common.sh": "dee644be8ab6236cb368a553493f55b53a90c3aead291550f7e635c080a5494f",
    "lib/platform-pki-csr-sign.sh": "8659a730f91c592c12fa3d40acbb080cf10d3eff6bd2de38fa486e8055f3e001",
}
REQUEST_ID = "0123456789abcdef0123456789abcdef"
EXPECTED_FILES = {
    "artifact",
    "tls.crt",
    "ca-chain.crt",
    "fullchain.crt",
    "response",
    "response.sig",
}
ARTIFACT_FIELDS = (
    "schema",
    "kind",
    "service",
    "request_id",
    "operation",
    "target",
    "source_kind",
    "source_response_sha256",
    "source_response_signature_sha256",
    "certificate_sha256",
    "certificate_spki_sha256",
    "chain_sha256",
    "fullchain_sha256",
    "issuer_root",
    "issuer_intermediate",
    "serial",
    "not_before_epoch",
    "not_after_epoch",
    "candidate_state",
    "deployment_state",
    "response_principal",
    "created_epoch",
)


def test_frozen_certificate_export_oracle_matches_provenance_and_modes() -> None:
    plan = (REPOSITORY / "docs/plans/platform-pki-python-migration.md").read_text(
        encoding="utf-8"
    )
    assert ORACLE_COMMIT in plan
    assert {
        path.relative_to(ORACLE_ROOT).as_posix()
        for path in ORACLE_ROOT.rglob("*")
    } == {"lib", *ORACLE_HASHES}
    for relative, expected in ORACLE_HASHES.items():
        path = ORACLE_ROOT / relative
        assert path.is_file() and not path.is_symlink()
        assert hashlib.sha256(path.read_bytes()).hexdigest() == expected
        expected_mode = 0o644 if relative.startswith("lib/") else 0o755
        assert stat.S_IMODE(path.stat().st_mode) == expected_mode


def test_certificate_export_compatibility_help_matches_oracle(
    process_runner, isolated_environment
) -> None:
    oracle_environment = environment(
        isolated_environment, PLATFORM_TOOLS_LIB_DIR=os.fspath(ORACLE_LIB)
    )
    for action in (("--help",), ("publish", "--help"), ("resolve", "--help")):
        oracle = process_runner([ORACLE, *action], env=oracle_environment, timeout=30)
        result = process_runner([EXPORT, *action], env=isolated_environment, timeout=30)
        assert result == ProcessResult(result.args, oracle.status, oracle.stdout, oracle.stderr)


def run(workspace: CsrWorkspace, *arguments: object):
    return workspace.runner(
        [EXPORT, *arguments, "--namespace", workspace.namespace],
        env=workspace.env,
        timeout=120,
    )


def publish(workspace: CsrWorkspace):
    return run(workspace, "publish", "external", "--request-id", REQUEST_ID)


def artifact_path(workspace: CsrWorkspace) -> Path:
    return workspace.pki / f"export/certificates/v1/artifacts/external/{REQUEST_ID}"


def _normalize_case_root(root: Path, value: str) -> str:
    return value.replace(os.fspath(root), "<case>")


def test_bash_python_publish_is_equivalent(
    csr_workspace: CsrWorkspace,
    tmp_path: Path,
) -> None:
    workspace = csr_workspace
    assert_result(workspace.issue(), 0)
    seed = workspace.namespace.parent
    differential = run_differential_case(
        seed,
        tmp_path / "publish-differential",
        Path("namespace/pki"),
        lambda root: (
            ORACLE,
            "publish",
            "external",
            "--request-id",
            REQUEST_ID,
            "--namespace",
            root / "namespace",
        ),
        lambda root: (
            UNIFIED,
            "certificate-export",
            "publish",
            "external",
            "--request-id",
            REQUEST_ID,
            "--namespace",
            root / "namespace",
        ),
        environment(workspace.env, PLATFORM_TOOLS_LIB_DIR=os.fspath(ORACLE_LIB)),
        output_normalizers=(_normalize_case_root,),
        run_options={"timeout": 120},
    )
    differential.assert_equivalent()


@pytest.mark.parametrize(
    ("arguments", "case_name"),
    (
        ((), "path"),
        (("--format", "json"), "json"),
        (("--manifest-sha256", "0" * 64), "wrong-pin"),
    ),
)
def test_bash_python_resolve_is_equivalent(
    csr_workspace: CsrWorkspace,
    tmp_path: Path,
    arguments: tuple[str, ...],
    case_name: str,
) -> None:
    workspace = csr_workspace
    assert_result(workspace.issue(), 0)
    assert_result(publish(workspace), 0)
    manifest_sha256 = digest(artifact_path(workspace) / "artifact")
    if arguments[:1] == ("--manifest-sha256",):
        pin_arguments = arguments
    else:
        pin_arguments = ("--manifest-sha256", manifest_sha256, *arguments)
    seed = workspace.namespace.parent
    differential = run_differential_case(
        seed,
        tmp_path / f"resolve-{case_name}-differential",
        Path("namespace/pki"),
        lambda root: (
            ORACLE,
            "resolve",
            "external",
            "--request-id",
            REQUEST_ID,
            *pin_arguments,
            "--namespace",
            root / "namespace",
        ),
        lambda root: (
            UNIFIED,
            "certificate-export",
            "resolve",
            "external",
            "--request-id",
            REQUEST_ID,
            *pin_arguments,
            "--namespace",
            root / "namespace",
        ),
        environment(workspace.env, PLATFORM_TOOLS_LIB_DIR=os.fspath(ORACLE_LIB)),
        output_normalizers=(_normalize_case_root,),
        run_options={"timeout": 120},
    )
    differential.assert_equivalent()


def wait_for_path(path: Path, timeout: float = 30) -> None:
    deadline = time.monotonic() + timeout
    while not path.exists():
        if time.monotonic() >= deadline:
            pytest.fail(f"timed out waiting for pause marker: {path}", pytrace=False)
        time.sleep(0.01)


def start_paused(process_starter, workspace: CsrWorkspace, arguments: list[object], point: str, marker: Path, release: Path, *, tmpdir: Path | None = None):
    env = {
        **workspace.env,
        "PLATFORM_PKI_CERTIFICATE_EXPORT_PAUSE_AT": point,
        "PLATFORM_PKI_CERTIFICATE_EXPORT_PAUSE_MARKER": os.fspath(marker),
        "PLATFORM_PKI_CERTIFICATE_EXPORT_PAUSE_RELEASE": os.fspath(release),
    }
    if tmpdir is not None:
        env["TMPDIR"] = os.fspath(tmpdir)
    return process_starter(
        [EXPORT, *arguments, "--namespace", workspace.namespace],
        env=env,
        timeout=120,
    )


def test_publish_bridges_real_csr_response_and_resolves_only_exact_pin(
    csr_workspace: CsrWorkspace,
) -> None:
    workspace = csr_workspace
    assert_result(workspace.issue(), 0)

    # Current trust may rotate after signing; export verification uses the retained
    # transaction snapshot that authenticated this exact historical response.
    requester_public = workspace.requester_key.with_suffix(".pub").read_text().split()
    write_private(
        workspace.pki / "inventory/csr-trust/responses.allowed_signers",
        f"offline-response {requester_public[0]} {requester_public[1]}\n",
    )

    result = publish(workspace)
    assert_result(result, 0)
    artifact = artifact_path(workspace)
    manifest = artifact / "artifact"
    manifest_sha256 = digest(manifest)
    assert f"manifest_sha256={manifest_sha256}\n" in result.stdout
    assert {path.name for path in artifact.iterdir()} == EXPECTED_FILES
    assert not list(artifact.rglob("*.key"))
    assert stat.S_IMODE(artifact.stat().st_mode) == 0o700
    assert artifact.stat().st_uid == os.getuid()
    for path in artifact.iterdir():
        metadata = path.stat()
        assert stat.S_IMODE(metadata.st_mode) == 0o600
        assert metadata.st_uid == os.getuid()
        assert metadata.st_nlink == 1

    lines = manifest.read_text(encoding="ascii").splitlines()
    assert tuple(line.partition("=")[0] for line in lines) == ARTIFACT_FIELDS
    assert manifest.read_bytes().endswith(b"\n")
    assert not manifest.read_bytes().endswith(b"\n\n")
    values = dict(line.split("=", 1) for line in lines)
    assert values["candidate_state"] == "pending"
    assert values["deployment_state"] == "unfinalized"
    assert "publication" not in values

    snapshot = tree_snapshot(artifact)
    assert_result(publish(workspace), 0)
    assert tree_snapshot(artifact) == snapshot

    pki_before_resolve = tree_snapshot(workspace.pki)
    resolved = run(
        workspace,
        "resolve",
        "external",
        "--request-id",
        REQUEST_ID,
        "--manifest-sha256",
        manifest_sha256,
    )
    assert_result(resolved, 0, stdout=f"{artifact.resolve()}\n", stderr="")
    assert tree_snapshot(workspace.pki) == pki_before_resolve
    resolved_json = run(
        workspace,
        "resolve",
        "external",
        "--request-id",
        REQUEST_ID,
        "--manifest-sha256",
        manifest_sha256,
        "--format",
        "json",
    )
    assert_result(resolved_json, 0)
    assert json.loads(resolved_json.stdout) == {
        "schema": 1,
        "kind": "certificate-export-resolution",
        "service": "external",
        "request_id": REQUEST_ID,
        "manifest_sha256": manifest_sha256,
        "path": os.fspath(artifact.resolve()),
        "candidate_state": "pending",
        "deployment_state": "unfinalized",
    }
    assert tree_snapshot(workspace.pki) == pki_before_resolve

    wrong_pin = run(
        workspace,
        "resolve",
        "external",
        "--request-id",
        REQUEST_ID,
        "--manifest-sha256",
        "0" * 64,
    )
    assert wrong_pin.status == 1
    assert wrong_pin.stdout == ""
    assert "does not match --manifest-sha256" in wrong_pin.stderr
    assert tree_snapshot(artifact) == snapshot

    no_implicit_selection = run(
        workspace,
        "resolve",
        "external",
        "--request-id",
        "1" * 32,
        "--manifest-sha256",
        manifest_sha256,
    )
    assert no_implicit_selection.status == 1
    assert no_implicit_selection.stdout == ""
    assert "CSR candidate artifact must be a non-symlink directory" in no_implicit_selection.stderr
    assert tree_snapshot(artifact) == snapshot


def test_publish_and_resolve_require_current_inventory_target(
    csr_workspace: CsrWorkspace,
) -> None:
    workspace = csr_workspace
    assert_result(workspace.issue(), 0)
    inventory = workspace.pki / "inventory/services.yml"
    original = inventory.read_text()
    write_private(inventory, original.replace("target: host-01", "target: host-02"))
    rejected_publish = publish(workspace)
    assert rejected_publish.status == 1
    assert "target does not match current inventory" in rejected_publish.stderr

    write_private(inventory, original)
    assert_result(publish(workspace), 0)
    manifest = artifact_path(workspace) / "artifact"
    write_private(inventory, original.replace("target: host-01", "target: host-02"))
    rejected_resolve = run(
        workspace,
        "resolve",
        "external",
        "--request-id",
        REQUEST_ID,
        "--manifest-sha256",
        digest(manifest),
    )
    assert rejected_resolve.status == 1
    assert "target does not match current inventory" in rejected_resolve.stderr


def test_publish_rejects_malformed_substituted_and_unsafe_source_or_destination(
    csr_workspace: CsrWorkspace,
) -> None:
    workspace = csr_workspace
    assert_result(workspace.issue(), 0)
    candidate = workspace.pki / f"state/csr/candidates/external/{REQUEST_ID}"
    response = workspace.pki / f"state/csr/responses/external/{REQUEST_ID}"
    artifact = artifact_path(workspace)

    (candidate / "tls.crt").chmod(0o644)
    malformed = publish(workspace)
    assert malformed.status == 1
    assert "unexpected or unsafe entries" in malformed.stderr
    assert not artifact.exists()
    (candidate / "tls.crt").chmod(0o600)

    original_signature = (response / "response.sig").read_bytes()
    original_candidate_signature = (candidate / "response.sig").read_bytes()
    original_candidate_record = (candidate / "candidate").read_text()
    substituted = workspace.artifacts / "request.sig"
    for path in (response / "response.sig", candidate / "response.sig"):
        path.write_bytes(substituted.read_bytes())
        path.chmod(0o600)
    candidate_record = original_candidate_record.replace(
        f"response_signature_sha256={digest(workspace.pki / f'state/csr/transactions/csr-{REQUEST_ID}/signing/response.sig')}\n",
        f"response_signature_sha256={digest(substituted)}\n",
    )
    write_private(candidate / "candidate", candidate_record)
    bad_signature = publish(workspace)
    assert bad_signature.status == 1
    assert "signature verification failed" in bad_signature.stderr
    assert not artifact.exists()
    (response / "response.sig").write_bytes(original_signature)
    (response / "response.sig").chmod(0o600)
    (candidate / "response.sig").write_bytes(original_candidate_signature)
    (candidate / "response.sig").chmod(0o600)
    write_private(candidate / "candidate", original_candidate_record)

    certificate_bytes = (candidate / "tls.crt").read_bytes()
    (candidate / "tls.crt").unlink()
    (candidate / "tls.crt").symlink_to(response / "tls.crt")
    unsafe_source = publish(workspace)
    assert unsafe_source.status == 1
    assert "unexpected or unsafe entries" in unsafe_source.stderr
    (candidate / "tls.crt").unlink()
    (candidate / "tls.crt").write_bytes(certificate_bytes)
    (candidate / "tls.crt").chmod(0o600)

    export_parent = workspace.pki / "export"
    for component in ("certificates", "v1", "artifacts", "external"):
        export_parent /= component
        export_parent.mkdir(mode=0o700)
    artifact.symlink_to(response, target_is_directory=True)
    unsafe_destination = publish(workspace)
    assert unsafe_destination.status == 1
    assert "destination is unsafe" in unsafe_destination.stderr
    artifact.unlink()
    assert_result(publish(workspace), 0)


def test_conflicting_export_fails_untouched_and_resolver_revalidates_embedded_files(
    csr_workspace: CsrWorkspace,
) -> None:
    workspace = csr_workspace
    assert_result(workspace.issue(), 0)
    assert_result(publish(workspace), 0)
    artifact = artifact_path(workspace)
    manifest_sha256 = digest(artifact / "artifact")
    manifest_bytes = (artifact / "artifact").read_bytes()
    (artifact / "artifact").write_bytes(manifest_bytes.rstrip(b"\n"))
    (artifact / "artifact").chmod(0o600)
    malformed_manifest = run(
        workspace,
        "resolve",
        "external",
        "--request-id",
        REQUEST_ID,
        "--manifest-sha256",
        manifest_sha256,
    )
    assert malformed_manifest.status == 1
    assert malformed_manifest.stdout == ""
    assert "not canonically newline-terminated" in malformed_manifest.stderr
    (artifact / "artifact").write_bytes(manifest_bytes)
    (artifact / "artifact").chmod(0o600)
    (artifact / "response.sig").write_bytes(b"substituted\n")
    (artifact / "response.sig").chmod(0o600)
    conflict = tree_snapshot(artifact)

    repeated = publish(workspace)
    assert repeated.status == 1
    assert "file digest validation failed" in repeated.stderr
    assert tree_snapshot(artifact) == conflict
    resolve = run(
        workspace,
        "resolve",
        "external",
        "--request-id",
        REQUEST_ID,
        "--manifest-sha256",
        manifest_sha256,
    )
    assert resolve.status == 1
    assert resolve.stdout == ""
    assert "file digest validation failed" in resolve.stderr
    assert tree_snapshot(artifact) == conflict


def test_export_obeys_locking_and_rejects_unresolved_state(
    csr_workspace: CsrWorkspace,
) -> None:
    workspace = csr_workspace
    assert_result(workspace.issue(), 0)
    journal = workspace.pki / "state/csr/recovery-journal"
    write_private(journal, "operation=csr-sign\n")
    unresolved = publish(workspace)
    assert unresolved.status == 1
    assert "recovery is required" in unresolved.stderr
    assert not artifact_path(workspace).exists()
    journal.unlink()

    export_lock = workspace.pki / "locks/export"
    export_lock.touch(mode=0o600)
    export_lock.chmod(0o600)
    expected = {
        "lifecycle": "Another PKI lifecycle operation is in progress",
        "root": "Another root CA operation is in progress",
        "intermediate": "Another intermediate CA operation is in progress",
        "inventory": "Another inventory operation is in progress",
        "export": "Another export operation is in progress",
    }
    for name, diagnostic in expected.items():
        with (workspace.pki / f"locks/{name}").open("r+") as lock_file:
            fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
            locked = publish(workspace)
            assert locked.status == 1
            assert diagnostic in locked.stderr
            assert not artifact_path(workspace).exists()
    assert_result(publish(workspace), 0)


def test_retained_trust_replacement_after_open_fails_and_cleans_snapshot(
    csr_workspace: CsrWorkspace,
    process_starter,
    tmp_path: Path,
) -> None:
    workspace = csr_workspace
    assert_result(workspace.issue(), 0)
    transaction = workspace.pki / f"state/csr/transactions/csr-{REQUEST_ID}"
    trust = transaction / "responses.allowed_signers"
    saved = transaction / "responses.allowed_signers.saved"
    marker = tmp_path / "trust-opened"
    release = tmp_path / "trust-release"
    command_tmp = tmp_path / "command-tmp"
    command_tmp.mkdir(mode=0o700)
    process = start_paused(
        process_starter,
        workspace,
        ["publish", "external", "--request-id", REQUEST_ID],
        "retained-trust-opened",
        marker,
        release,
        tmpdir=command_tmp,
    )
    wait_for_path(marker)
    trust.rename(saved)
    requester_public = workspace.requester_key.with_suffix(".pub").read_text().split()
    write_private(trust, f"offline-response {requester_public[0]} {requester_public[1]}\n")
    release.touch()
    result = process.wait()
    assert result.status == 1
    assert result.stdout == ""
    assert "Retained CSR response trust snapshot changed while being copied" in result.stderr
    assert not artifact_path(workspace).exists()
    assert not any(command_tmp.iterdir())
    trust.unlink()
    saved.rename(trust)
    assert_result(publish(workspace), 0)


def test_resolver_rejects_directory_and_file_replacement_before_output(
    csr_workspace: CsrWorkspace,
    process_starter,
    tmp_path: Path,
) -> None:
    workspace = csr_workspace
    assert_result(workspace.issue(), 0)
    assert_result(publish(workspace), 0)
    artifact = artifact_path(workspace)
    manifest_sha256 = digest(artifact / "artifact")
    resolve_arguments: list[object] = [
        "resolve",
        "external",
        "--request-id",
        REQUEST_ID,
        "--manifest-sha256",
        manifest_sha256,
    ]

    marker = tmp_path / "directory-validated"
    release = tmp_path / "directory-release"
    process = start_paused(process_starter, workspace, resolve_arguments, "resolver-before-output", marker, release)
    wait_for_path(marker)
    saved_artifact = artifact.with_name(f"{REQUEST_ID}.saved")
    artifact.rename(saved_artifact)
    shutil.copytree(saved_artifact, artifact)
    release.touch()
    directory_result = process.wait()
    assert directory_result.status == 1
    assert directory_result.stdout == ""
    assert "artifact directory identity changed after validation" in directory_result.stderr
    shutil.rmtree(artifact)
    saved_artifact.rename(artifact)

    marker = tmp_path / "file-validated"
    release = tmp_path / "file-release"
    process = start_paused(process_starter, workspace, resolve_arguments, "resolver-before-output", marker, release)
    wait_for_path(marker)
    certificate = artifact / "tls.crt"
    saved_certificate = artifact.parent / "tls.crt.saved"
    certificate.rename(saved_certificate)
    shutil.copy2(saved_certificate, certificate)
    certificate.chmod(0o600)
    release.touch()
    file_result = process.wait()
    assert file_result.status == 1
    assert file_result.stdout == ""
    assert "artifact file identity changed after validation: tls.crt" in file_result.stderr
    certificate.unlink()
    saved_certificate.rename(certificate)
    assert_result(
        run(workspace, *resolve_arguments),
        0,
        stdout=f"{artifact.resolve()}\n",
        stderr="",
    )


def test_publish_no_clobber_race_preserves_competing_destination(
    csr_workspace: CsrWorkspace,
    process_starter,
    tmp_path: Path,
) -> None:
    workspace = csr_workspace
    assert_result(workspace.issue(), 0)
    marker = tmp_path / "publish-ready"
    release = tmp_path / "publish-release"
    process = start_paused(
        process_starter,
        workspace,
        ["publish", "external", "--request-id", REQUEST_ID],
        "publish-before-rename",
        marker,
        release,
    )
    wait_for_path(marker)
    artifact = artifact_path(workspace)
    artifact.mkdir(mode=0o700)
    write_private(artifact / "foreign", "competing publication\n")
    release.touch()
    result = process.wait()
    assert result.status == 1
    assert "Cannot publish immutable certificate export" in result.stderr
    assert (artifact / "foreign").read_text() == "competing publication\n"
    assert {path.name for path in artifact.parent.iterdir()} == {REQUEST_ID}
    (artifact / "foreign").unlink()
    artifact.rmdir()
    assert_result(publish(workspace), 0)


@pytest.mark.parametrize(
    ("action", "pause_point"),
    (("publish", "publish-before-rename"), ("resolve", "resolver-before-output")),
)
def test_final_source_replacement_fails_cleanly_before_publication_or_output(
    csr_workspace: CsrWorkspace,
    process_starter,
    tmp_path: Path,
    action: str,
    pause_point: str,
) -> None:
    workspace = csr_workspace
    assert_result(workspace.issue(), 0)
    artifact = artifact_path(workspace)
    if action == "resolve":
        assert_result(publish(workspace), 0)
        arguments: list[object] = [
            "resolve",
            "external",
            "--request-id",
            REQUEST_ID,
            "--manifest-sha256",
            digest(artifact / "artifact"),
        ]
    else:
        arguments = ["publish", "external", "--request-id", REQUEST_ID]
    marker = tmp_path / f"{action}-source-validated"
    release = tmp_path / f"{action}-source-release"
    process = start_paused(
        process_starter, workspace, arguments, pause_point, marker, release
    )
    wait_for_path(marker)
    source = workspace.pki / f"state/csr/candidates/external/{REQUEST_ID}/tls.crt"
    saved = source.with_name("tls.crt.saved")
    source.rename(saved)
    shutil.copy2(saved, source)
    source.chmod(0o600)
    release.touch()
    result = process.wait()
    assert result.status == 1
    assert result.stdout == ""
    assert "CSR historical evidence changed during validation" in result.stderr
    assert "Traceback" not in result.stderr
    if action == "publish":
        assert not artifact.exists()
        assert not any(
            path.name.startswith(f".platform-pki-certificate-export.{REQUEST_ID}.")
            for path in artifact.parent.iterdir()
        )
    else:
        assert artifact.is_dir()


def test_parser_requires_explicit_request_and_manifest_pin(
    csr_workspace: CsrWorkspace,
) -> None:
    workspace = csr_workspace
    missing_request = workspace.runner(
        [EXPORT, "publish", "external", "--namespace", workspace.namespace],
        env=workspace.env,
    )
    assert missing_request.status == 1
    assert missing_request.stdout == ""
    missing_pin = workspace.runner(
        [
            EXPORT,
            "resolve",
            "external",
            "--request-id",
            REQUEST_ID,
            "--namespace",
            workspace.namespace,
        ],
        env=workspace.env,
    )
    assert missing_pin.status == 1
    assert missing_pin.stdout == ""
    assert not (workspace.pki / "export/certificates").exists()
