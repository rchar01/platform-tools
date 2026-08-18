from __future__ import annotations

import json
import os
import shutil
import stat
import time
from pathlib import Path

import pytest

from src.platform_pki.csr_outcome import CSR_OUTCOME_FIELDS

from .support import BIN, assert_result, digest, write_private
from .test_csr_candidate import REQUEST_ID, decide, prepare
from .test_csr_signing import CsrWorkspace, csr_workspace, sign, tree_snapshot


pytestmark = pytest.mark.pki
OUTCOME = (BIN / "platform-pki", "csr-outcome")
EXPECTED_FILES = {
    "outcome",
    "outcome.sig",
    "deployment",
    "deployment.sig",
    "deployers.allowed_signers",
    "decision",
}


def run(workspace: CsrWorkspace, *arguments: object):
    return workspace.runner(
        [*OUTCOME, *arguments, "--namespace", workspace.namespace],
        env=workspace.env,
        timeout=120,
    )


def wait_for_path(path: Path, process, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    while not path.exists():
        observation = process.observe()
        if observation.status is not None:
            pytest.fail(f"process exited before pause marker: {observation}")
        if time.monotonic() >= deadline:
            pytest.fail(f"timed out waiting for pause marker: {path}")
        time.sleep(0.01)


def export_path(workspace: CsrWorkspace, request_id: str = REQUEST_ID) -> Path:
    return (
        workspace.pki
        / f"export/csr-outcomes/v1/artifacts/external/{request_id}"
    )


def terminalize(workspace: CsrWorkspace, action: str = "finalize") -> None:
    artifact, manifest = prepare(workspace)
    result = "activated" if action == "finalize" else "not-activated"
    assert_result(
        decide(
            workspace,
            REQUEST_ID,
            artifact,
            manifest,
            action=action,
            result=result,
        ),
        0,
    )


def publish(workspace: CsrWorkspace, key: Path | None = None):
    return run(
        workspace,
        "publish",
        "external",
        "--request-id",
        REQUEST_ID,
        "--outcome-key",
        workspace.response_key if key is None else key,
    )


def resolve(
    workspace: CsrWorkspace,
    manifest_sha256: str | None = None,
    *,
    output_format: str = "path",
    request_id: str = REQUEST_ID,
    service: str = "external",
):
    artifact = export_path(workspace, request_id)
    pin = digest(artifact / "outcome") if manifest_sha256 is None else manifest_sha256
    return run(
        workspace,
        "resolve",
        service,
        "--request-id",
        request_id,
        "--manifest-sha256",
        pin,
        "--format",
        output_format,
    )


@pytest.mark.parametrize(
    ("action", "state"),
    (("finalize", "finalized"), ("abandon", "abandoned")),
)
def test_publish_and_resolve_authenticated_terminal_outcome(
    csr_workspace: CsrWorkspace, action: str, state: str
) -> None:
    terminalize(csr_workspace, action)
    result = publish(csr_workspace)
    assert_result(result, 0)
    artifact = export_path(csr_workspace)
    manifest_sha256 = digest(artifact / "outcome")
    assert json.loads(result.stdout) == {
        "status": "created",
        "service": "external",
        "request_id": REQUEST_ID,
        "path": os.fspath(artifact),
        "manifest_sha256": manifest_sha256,
    }
    assert os.fspath(csr_workspace.response_key) not in result.stdout + result.stderr
    assert {item.name for item in artifact.iterdir()} == EXPECTED_FILES
    assert stat.S_IMODE(artifact.stat().st_mode) == 0o700
    assert artifact.stat().st_uid == os.getuid()
    for item in artifact.iterdir():
        metadata = item.stat()
        assert stat.S_IMODE(metadata.st_mode) == 0o600
        assert metadata.st_uid == os.getuid()
        assert metadata.st_nlink == 1

    lines = (artifact / "outcome").read_text(encoding="ascii").splitlines()
    assert tuple(line.partition("=")[0] for line in lines) == CSR_OUTCOME_FIELDS
    values = dict(line.split("=", 1) for line in lines)
    response = dict(
        line.split("=", 1)
        for line in (
            csr_workspace.pki
            / f"state/csr/responses/external/{REQUEST_ID}/response"
        )
        .read_text(encoding="ascii")
        .splitlines()
    )
    assert values["schema"] == "1"
    assert values["kind"] == "csr-signer-outcome"
    assert values["action"] == action
    assert values["state"] == state
    assert values["outcome_principal"] == response["response_principal"]
    assert values["decision_sha256"] == digest(
        csr_workspace.pki / f"state/csr/outcomes/external/{REQUEST_ID}/decision"
    )

    snapshot = tree_snapshot(artifact)
    repeated = publish(csr_workspace)
    assert_result(repeated, 0)
    assert json.loads(repeated.stdout)["status"] == "existing"
    assert tree_snapshot(artifact) == snapshot
    wrong_existing = publish(csr_workspace, csr_workspace.requester_key)
    assert wrong_existing.status == 1
    assert "does not match the retained response signer" in wrong_existing.stderr
    assert tree_snapshot(artifact) == snapshot

    assert_result(
        resolve(csr_workspace),
        0,
        stdout=f"{artifact}\n",
        stderr="",
    )
    resolved = resolve(csr_workspace, output_format="json")
    assert_result(resolved, 0)
    assert json.loads(resolved.stdout) == {
        "schema": 1,
        "kind": "csr-outcome-export-resolution",
        "service": "external",
        "request_id": REQUEST_ID,
        "manifest_sha256": manifest_sha256,
        "path": os.fspath(artifact),
        "action": action,
        "state": state,
        "live_target_state_claimed": False,
    }


def test_publish_rejects_wrong_key_and_nonabsolute_key(
    csr_workspace: CsrWorkspace,
) -> None:
    terminalize(csr_workspace)
    wrong = publish(csr_workspace, csr_workspace.requester_key)
    assert wrong.status == 1
    assert "does not match the retained response signer" in wrong.stderr
    assert not export_path(csr_workspace).exists()

    relative = run(
        csr_workspace,
        "publish",
        "external",
        "--request-id",
        REQUEST_ID,
        "--outcome-key",
        "relative-key",
    )
    assert relative.status == 1
    assert "signing key path is invalid" in relative.stderr
    assert not export_path(csr_workspace).exists()


@pytest.mark.parametrize("mutation", ("reordered", "extra", "principal"))
def test_resolve_rejects_noncanonical_or_wrong_principal_manifest(
    csr_workspace: CsrWorkspace, mutation: str
) -> None:
    terminalize(csr_workspace)
    assert_result(publish(csr_workspace), 0)
    manifest = export_path(csr_workspace) / "outcome"
    original_digest = digest(manifest)
    lines = manifest.read_text(encoding="ascii").splitlines()
    if mutation == "reordered":
        lines[0], lines[1] = lines[1], lines[0]
    elif mutation == "extra":
        lines.append("extra=value")
    else:
        lines[-1] = "outcome_principal=wrong-principal"
    write_private(manifest, "\n".join(lines) + "\n")

    result = resolve(csr_workspace, original_digest)
    assert result.status == 1
    assert result.stdout == ""
    assert "manifest" in result.stderr


def test_resolve_rejects_wrong_signature_namespace(
    csr_workspace: CsrWorkspace,
) -> None:
    terminalize(csr_workspace)
    assert_result(publish(csr_workspace), 0)
    artifact = export_path(csr_workspace)
    manifest_sha256 = digest(artifact / "outcome")
    (artifact / "outcome.sig").unlink()
    sign(
        csr_workspace.runner,
        csr_workspace.env,
        csr_workspace.response_key,
        "platform-pki-csr-outcome-wrong",
        artifact / "outcome",
    )

    result = resolve(csr_workspace, manifest_sha256)
    assert result.status == 1
    assert "signature verification failed" in result.stderr


@pytest.mark.parametrize("tamper", ("decision", "outcome-digest"))
def test_resolve_rejects_source_divergence_resigned_by_valid_key(
    csr_workspace: CsrWorkspace, tamper: str
) -> None:
    terminalize(csr_workspace)
    assert_result(publish(csr_workspace), 0)
    artifact = export_path(csr_workspace)
    manifest = artifact / "outcome"
    manifest_text = manifest.read_text(encoding="ascii")
    if tamper == "decision":
        decision = artifact / "decision"
        write_private(
            decision,
            decision.read_text(encoding="ascii").replace(
                "state=finalized\n", "state=abandoned\n"
            ),
        )
        fields = dict(
            line.split("=", 1) for line in manifest_text.splitlines()
        )
        manifest_text = manifest_text.replace(
            f"decision_sha256={fields['decision_sha256']}\n",
            f"decision_sha256={digest(decision)}\n",
        )
    else:
        fields = dict(
            line.split("=", 1) for line in manifest_text.splitlines()
        )
        manifest_text = manifest_text.replace(
            f"deployment_sha256={fields['deployment_sha256']}\n",
            f"deployment_sha256={'0' * 64}\n",
        )
    write_private(manifest, manifest_text)
    (artifact / "outcome.sig").unlink()
    sign(
        csr_workspace.runner,
        csr_workspace.env,
        csr_workspace.response_key,
        "platform-pki-csr-outcome-v1",
        manifest,
    )

    result = resolve(csr_workspace, digest(manifest))
    assert result.status == 1
    assert result.stdout == ""
    assert "manifest binding failed" in result.stderr


@pytest.mark.parametrize(
    "hazard", ("mode", "symlink", "hardlink", "unexpected")
)
def test_resolve_rejects_unsafe_package_entries(
    csr_workspace: CsrWorkspace, tmp_path: Path, hazard: str
) -> None:
    terminalize(csr_workspace)
    assert_result(publish(csr_workspace), 0)
    artifact = export_path(csr_workspace)
    manifest_sha256 = digest(artifact / "outcome")
    deployment = artifact / "deployment"
    if hazard == "mode":
        deployment.chmod(0o644)
    elif hazard == "symlink":
        deployment.unlink()
        deployment.symlink_to(
            csr_workspace.pki
            / f"state/csr/outcomes/external/{REQUEST_ID}/deployment"
        )
    elif hazard == "hardlink":
        os.link(deployment, tmp_path / "deployment-link")
    else:
        write_private(artifact / "unexpected", "unexpected\n")

    result = resolve(csr_workspace, manifest_sha256)
    assert result.status == 1
    assert "unexpected or unsafe entries" in result.stderr


@pytest.mark.parametrize("replacement", ("package", "source"))
def test_resolve_rejects_package_or_authenticated_source_replacement(
    csr_workspace: CsrWorkspace, replacement: str
) -> None:
    terminalize(csr_workspace)
    assert_result(publish(csr_workspace), 0)
    artifact = export_path(csr_workspace)
    manifest_sha256 = digest(artifact / "outcome")
    if replacement == "package":
        write_private(artifact / "decision", "replaced\n")
    else:
        source = (
            csr_workspace.pki
            / f"state/csr/outcomes/external/{REQUEST_ID}/decision"
        )
        write_private(source, source.read_text(encoding="ascii") + "extra=value\n")

    result = resolve(csr_workspace, manifest_sha256)
    assert result.status == 1
    assert result.stdout == ""


def test_wrong_coordinates_digest_and_conflicting_publication_fail_closed(
    csr_workspace: CsrWorkspace,
) -> None:
    terminalize(csr_workspace)
    assert_result(publish(csr_workspace), 0)
    artifact = export_path(csr_workspace)
    manifest_sha256 = digest(artifact / "outcome")

    for result in (
        resolve(csr_workspace, "0" * 64),
        resolve(csr_workspace, manifest_sha256, request_id="1" * 32),
        resolve(csr_workspace, manifest_sha256, service="missing"),
    ):
        assert result.status == 1
        assert result.stdout == ""

    manifest = artifact / "outcome"
    write_private(
        manifest,
        manifest.read_text(encoding="ascii").replace(
            "kind=csr-signer-outcome\n", "kind=conflicting-outcome\n"
        ),
    )
    conflict = tree_snapshot(artifact)
    repeated = publish(csr_workspace)
    assert repeated.status == 1
    assert tree_snapshot(artifact) == conflict


def test_pending_and_recovery_required_state_are_never_exported(
    csr_workspace: CsrWorkspace,
) -> None:
    artifact, manifest = prepare(csr_workspace)
    pending = publish(csr_workspace)
    assert pending.status == 1
    assert not export_path(csr_workspace).exists()

    assert_result(
        decide(
            csr_workspace,
            REQUEST_ID,
            artifact,
            manifest,
            action="abandon",
            result="not-activated",
        ),
        0,
    )
    assert_result(publish(csr_workspace), 0)
    journal = csr_workspace.pki / "state/csr/recovery-journal"
    write_private(journal, "operation=csr-sign\n")
    blocked = resolve(csr_workspace)
    assert blocked.status == 1
    assert "recovery is required" in blocked.stderr


@pytest.mark.parametrize("replacement", ("source", "package"))
def test_final_identity_rechecks_reject_same_byte_replacement(
    csr_workspace: CsrWorkspace,
    process_starter,
    tmp_path: Path,
    replacement: str,
) -> None:
    terminalize(csr_workspace)
    marker = tmp_path / f"{replacement}-validated"
    release = tmp_path / f"{replacement}-release"
    env = {
        **csr_workspace.env,
        "PLATFORM_PKI_CSR_OUTCOME_PAUSE_AT": (
            "publish-before-rename"
            if replacement == "source"
            else "resolver-before-output"
        ),
        "PLATFORM_PKI_CSR_OUTCOME_PAUSE_MARKER": os.fspath(marker),
        "PLATFORM_PKI_CSR_OUTCOME_PAUSE_RELEASE": os.fspath(release),
    }
    if replacement == "source":
        arguments: list[object] = [
            *OUTCOME,
            "publish",
            "external",
            "--request-id",
            REQUEST_ID,
            "--outcome-key",
            csr_workspace.response_key,
            "--namespace",
            csr_workspace.namespace,
        ]
        replaced = (
            csr_workspace.pki
            / f"state/csr/outcomes/external/{REQUEST_ID}/decision"
        )
    else:
        assert_result(publish(csr_workspace), 0)
        artifact = export_path(csr_workspace)
        arguments = [
            *OUTCOME,
            "resolve",
            "external",
            "--request-id",
            REQUEST_ID,
            "--manifest-sha256",
            digest(artifact / "outcome"),
            "--namespace",
            csr_workspace.namespace,
        ]
        replaced = artifact / "deployment"
    process = process_starter(arguments, env=env, timeout=120)
    wait_for_path(marker, process)
    saved = replaced.with_name(f"{replaced.name}.saved")
    replaced.rename(saved)
    shutil.copy2(saved, replaced)
    replaced.chmod(0o600)
    release.touch()

    result = process.wait()
    assert result.status == 1
    assert result.stdout == ""
    assert "changed" in result.stderr
    if replacement == "source":
        assert not export_path(csr_workspace).exists()


@pytest.mark.parametrize("winner", ("exact", "conflicting"))
def test_publication_destination_race_accepts_only_exact_winner(
    csr_workspace: CsrWorkspace,
    process_starter,
    tmp_path: Path,
    winner: str,
) -> None:
    terminalize(csr_workspace)
    assert_result(publish(csr_workspace), 0)
    artifact = export_path(csr_workspace)
    template = tmp_path / "outcome-template"
    shutil.copytree(artifact, template)
    shutil.rmtree(artifact)
    marker = tmp_path / f"destination-{winner}-validated"
    release = tmp_path / f"destination-{winner}-release"
    env = {
        **csr_workspace.env,
        "PLATFORM_PKI_CSR_OUTCOME_PAUSE_AT": "publish-before-rename",
        "PLATFORM_PKI_CSR_OUTCOME_PAUSE_MARKER": os.fspath(marker),
        "PLATFORM_PKI_CSR_OUTCOME_PAUSE_RELEASE": os.fspath(release),
    }
    process = process_starter(
        [
            *OUTCOME,
            "publish",
            "external",
            "--request-id",
            REQUEST_ID,
            "--outcome-key",
            csr_workspace.response_key,
            "--namespace",
            csr_workspace.namespace,
        ],
        env=env,
        timeout=120,
    )
    wait_for_path(marker, process)
    shutil.copytree(template, artifact)
    if winner == "conflicting":
        decision = artifact / "decision"
        write_private(
            decision,
            decision.read_text(encoding="ascii") + "conflict=value\n",
        )
    winning_snapshot = tree_snapshot(artifact)
    release.touch()

    result = process.wait()
    if winner == "exact":
        assert_result(result, 0)
        assert json.loads(result.stdout)["status"] == "existing"
    else:
        assert result.status == 1
        assert result.stdout == ""
    assert tree_snapshot(artifact) == winning_snapshot
    assert not tuple(
        artifact.parent.glob(".platform-pki-csr-outcome-export.*")
    )


@pytest.mark.parametrize("operation", ("created", "existing", "resolve"))
@pytest.mark.parametrize("replacement", ("same-byte", "conflicting"))
def test_artifact_parent_replacement_race_fails_closed(
    csr_workspace: CsrWorkspace,
    process_starter,
    tmp_path: Path,
    operation: str,
    replacement: str,
) -> None:
    terminalize(csr_workspace)
    artifact = export_path(csr_workspace)
    if operation != "created":
        assert_result(publish(csr_workspace), 0)
    if operation == "resolve":
        arguments: list[object] = [
            *OUTCOME,
            "resolve",
            "external",
            "--request-id",
            REQUEST_ID,
            "--manifest-sha256",
            digest(artifact / "outcome"),
            "--namespace",
            csr_workspace.namespace,
        ]
        pause_at = "resolver-before-output"
    else:
        arguments = [
            *OUTCOME,
            "publish",
            "external",
            "--request-id",
            REQUEST_ID,
            "--outcome-key",
            csr_workspace.response_key,
            "--namespace",
            csr_workspace.namespace,
        ]
        pause_at = (
            "publish-before-rename"
            if operation == "created"
            else "publish-existing-before-output"
        )
    marker = tmp_path / f"parent-{operation}-{replacement}-validated"
    release = tmp_path / f"parent-{operation}-{replacement}-release"
    env = {
        **csr_workspace.env,
        "PLATFORM_PKI_CSR_OUTCOME_PAUSE_AT": pause_at,
        "PLATFORM_PKI_CSR_OUTCOME_PAUSE_MARKER": os.fspath(marker),
        "PLATFORM_PKI_CSR_OUTCOME_PAUSE_RELEASE": os.fspath(release),
    }
    process = process_starter(arguments, env=env, timeout=120)
    wait_for_path(marker, process)
    parent = artifact.parent
    saved = parent.with_name("external.saved")
    parent.rename(saved)
    if replacement == "same-byte":
        shutil.copytree(saved, parent)
    else:
        parent.mkdir(mode=0o700)
    release.touch()

    result = process.wait()
    assert result.status == 1
    assert result.stdout == ""
    if operation == "created":
        assert (
            "Publication object identity changed" in result.stderr
            or "parent path changed during validation" in result.stderr
        )
    else:
        assert (
            "export changed after validation" in result.stderr
            or "parent path changed during validation" in result.stderr
        )


@pytest.mark.parametrize("replacement", ("package", "source"))
def test_created_publication_rechecks_artifact_and_source_before_output(
    csr_workspace: CsrWorkspace,
    process_starter,
    tmp_path: Path,
    replacement: str,
) -> None:
    terminalize(csr_workspace)
    artifact = export_path(csr_workspace)
    marker = tmp_path / f"created-{replacement}-validated"
    release = tmp_path / f"created-{replacement}-release"
    env = {
        **csr_workspace.env,
        "PLATFORM_PKI_CSR_OUTCOME_PAUSE_AT": "publish-created-before-output",
        "PLATFORM_PKI_CSR_OUTCOME_PAUSE_MARKER": os.fspath(marker),
        "PLATFORM_PKI_CSR_OUTCOME_PAUSE_RELEASE": os.fspath(release),
    }
    process = process_starter(
        [
            *OUTCOME,
            "publish",
            "external",
            "--request-id",
            REQUEST_ID,
            "--outcome-key",
            csr_workspace.response_key,
            "--namespace",
            csr_workspace.namespace,
        ],
        env=env,
        timeout=120,
    )
    wait_for_path(marker, process)
    replaced = (
        artifact / "deployment"
        if replacement == "package"
        else csr_workspace.pki
        / f"state/csr/outcomes/external/{REQUEST_ID}/decision"
    )
    saved = replaced.with_name(f"{replaced.name}.saved")
    replaced.rename(saved)
    shutil.copy2(saved, replaced)
    replaced.chmod(0o600)
    release.touch()

    result = process.wait()
    assert result.status == 1
    assert result.stdout == ""
    assert "changed" in result.stderr


@pytest.mark.parametrize("operation", ("publish", "resolve"))
@pytest.mark.parametrize("replacement", ("same-byte", "conflicting"))
def test_retained_response_trust_replacement_race_fails_closed(
    csr_workspace: CsrWorkspace,
    process_starter,
    tmp_path: Path,
    operation: str,
    replacement: str,
) -> None:
    terminalize(csr_workspace)
    artifact = export_path(csr_workspace)
    if operation == "publish":
        arguments: list[object] = [
            *OUTCOME,
            "publish",
            "external",
            "--request-id",
            REQUEST_ID,
            "--outcome-key",
            csr_workspace.response_key,
            "--namespace",
            csr_workspace.namespace,
        ]
        pause_at = "publish-before-rename"
    else:
        assert_result(publish(csr_workspace), 0)
        arguments = [
            *OUTCOME,
            "resolve",
            "external",
            "--request-id",
            REQUEST_ID,
            "--manifest-sha256",
            digest(artifact / "outcome"),
            "--namespace",
            csr_workspace.namespace,
        ]
        pause_at = "resolver-before-output"
    marker = tmp_path / f"{operation}-{replacement}-validated"
    release = tmp_path / f"{operation}-{replacement}-release"
    env = {
        **csr_workspace.env,
        "PLATFORM_PKI_CSR_OUTCOME_PAUSE_AT": pause_at,
        "PLATFORM_PKI_CSR_OUTCOME_PAUSE_MARKER": os.fspath(marker),
        "PLATFORM_PKI_CSR_OUTCOME_PAUSE_RELEASE": os.fspath(release),
    }
    process = process_starter(arguments, env=env, timeout=120)
    wait_for_path(marker, process)

    transaction = (
        csr_workspace.pki / f"state/csr/transactions/csr-{REQUEST_ID}"
    )
    trust = transaction / "responses.allowed_signers"
    saved = transaction / "responses.allowed_signers.saved"
    trust.rename(saved)
    if replacement == "same-byte":
        shutil.copy2(saved, trust)
        trust.chmod(0o600)
    else:
        requester_public = (
            csr_workspace.requester_key.with_suffix(".pub").read_text().split()
        )
        write_private(
            trust,
            f"offline-response {requester_public[0]} {requester_public[1]}\n",
        )
    release.touch()

    result = process.wait()
    assert result.status == 1
    assert result.stdout == ""
    assert "historical evidence changed during validation" in result.stderr
    if operation == "publish":
        assert not artifact.exists()


def test_parser_requires_explicit_publish_key_and_resolve_digest(
    csr_workspace: CsrWorkspace,
) -> None:
    missing_key = run(
        csr_workspace, "publish", "external", "--request-id", REQUEST_ID
    )
    assert missing_key.status == 1
    assert missing_key.stdout == ""
    missing_digest = run(
        csr_workspace, "resolve", "external", "--request-id", REQUEST_ID
    )
    assert missing_digest.status == 1
    assert missing_digest.stdout == ""
    assert not (csr_workspace.pki / "export/csr-outcomes").exists()
