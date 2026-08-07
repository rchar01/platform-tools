from __future__ import annotations

import json
import signal
import time
from pathlib import Path

import pytest

from .support import BIN, assert_result, digest, environment, write_private
from .test_csr_signing import (
    EXPORT as ANSIBLE_EXPORT,
    INVENTORY,
    ISSUE,
    POLICY,
    CsrWorkspace,
    RENEW,
    csr_workspace,
    sign,
    tree_snapshot,
    write_exchange,
)


pytestmark = pytest.mark.pki
CANDIDATE = BIN / "platform-pki-csr-candidate"
CERTIFICATE_EXPORT = BIN / "platform-pki-certificate-export"
TRUST_INSTALL = BIN / "platform-pki-csr-trust-install"
RECOVER = BIN / "platform-pki-csr-recover"
REQUEST_ID = "0123456789abcdef0123456789abcdef"
POLICY2 = """schema=2
request_namespace=platform-pki-csr-request-v1
approval_namespace=platform-pki-csr-approval-v1
response_namespace=platform-pki-csr-response-v1
deployment_namespace=platform-pki-csr-deployment-v1
request_max_age_seconds=604800
sole_operator_min_delay_seconds=86400
approval_max_age_seconds=86400
deployment_max_age_seconds=86400
clock_skew_seconds=300
approver_principal=offline-approver
response_principal=offline-response
"""


def run(workspace: CsrWorkspace, *arguments: object):
    return workspace.runner(
        [CANDIDATE, *arguments, "--namespace", workspace.namespace],
        env=workspace.env,
        timeout=120,
    )


def prepare(workspace: CsrWorkspace) -> tuple[Path, str]:
    install_deployer_trust(workspace)
    assert_result(workspace.issue(), 0)
    assert_result(
        workspace.runner(
            [
                CERTIFICATE_EXPORT,
                "publish",
                "external",
                "--request-id",
                REQUEST_ID,
                "--namespace",
                workspace.namespace,
            ],
            env=workspace.env,
            timeout=120,
        ),
        0,
    )
    artifact = (
        workspace.pki
        / f"export/certificates/v1/artifacts/external/{REQUEST_ID}"
    )
    return artifact, digest(artifact / "artifact")


def install_deployer_trust(workspace: CsrWorkspace) -> None:
    configure_deployer_trust(workspace)
    assert_result(
        workspace.runner(
            [
                TRUST_INSTALL,
                "--namespace",
                workspace.namespace,
                "--private-repo",
                workspace.private,
            ],
            env=workspace.env,
            timeout=120,
        ),
        0,
    )


def configure_deployer_trust(workspace: CsrWorkspace) -> None:
    trust = workspace.private / "pki/csr-trust"
    write_private(trust / "policy", POLICY2)
    requester = workspace.requester_key.with_suffix(".pub").read_text().split()
    write_private(
        trust / "deployers.allowed_signers",
        f"host-01 {requester[0]} {requester[1]}\n",
    )


def write_evidence(
    workspace: CsrWorkspace,
    artifact: Path,
    *,
    action: str,
    result: str,
    nonce: str | None = None,
    request_id: str = REQUEST_ID,
    predecessor_certificate_sha256: str | None = None,
    predecessor_intermediate_sha256: str | None = None,
) -> tuple[Path, Path]:
    response = workspace.pki / f"state/csr/responses/external/{request_id}"
    candidate = workspace.pki / f"state/csr/candidates/external/{request_id}"
    values = dict(
        line.split("=", 1)
        for line in (response / "response").read_text().splitlines()
    )
    now = int(time.time())
    activated = result == "activated"
    rolled_back = result == "rolled-back"
    evidence = workspace.artifacts / f"deployment-{action}-{request_id}"
    has_predecessor = values["operation"] != "issue"
    content = {
        "schema": "1",
        "request_id": request_id,
        "nonce": values["nonce"] if nonce is None else nonce,
        "operation": values["operation"],
        "service": "external",
        "target": "host-01",
        "request_sha256": values["request_sha256"],
        "response_sha256": digest(response / "response"),
        "response_signature_sha256": digest(response / "response.sig"),
        "candidate_sha256": digest(candidate / "candidate"),
        "artifact_request_id": request_id,
        "artifact_manifest_sha256": digest(artifact / "artifact"),
        "certificate_sha256": digest(artifact / "tls.crt"),
        "certificate_spki_sha256": values["certificate_spki_sha256"],
        "chain_sha256": digest(artifact / "ca-chain.crt"),
        "fullchain_sha256": digest(artifact / "fullchain.crt"),
        "action": action,
        "result": result,
        "local_certificate_sha256": digest(artifact / "tls.crt"),
        "local_key_spki_sha256": values["certificate_spki_sha256"],
        "local_key_certificate_match": "true",
        "served_certificate_sha256": predecessor_certificate_sha256 if rolled_back else digest(artifact / "tls.crt") if activated else "none",
        "served_intermediate_sha256": predecessor_intermediate_sha256 if rolled_back else digest(workspace.pki / "authorities/intermediates/g1-i1/certs/intermediate-ca.crt") if activated else "none",
        "validation_boundary_sha256": "0" * 64,
        "validation_result": "passed" if activated or rolled_back else "not-run",
        "activation_epoch": str(now - 2) if activated or rolled_back else "none",
        "validation_epoch": str(now - 1) if activated or rolled_back else "none",
        "rollback_state": "restored" if rolled_back else "retained" if activated and has_predecessor else "none",
        "rollback_hold_until_epoch": str(now + 3600) if rolled_back or activated and has_predecessor else "none",
        "deployment_principal": "host-01",
        "created_epoch": str(now),
        "expires_epoch": str(now + 3600),
    }
    fields = (
        "schema request_id nonce operation service target request_sha256 response_sha256 "
        "response_signature_sha256 candidate_sha256 artifact_request_id artifact_manifest_sha256 "
        "certificate_sha256 certificate_spki_sha256 chain_sha256 fullchain_sha256 action result "
        "local_certificate_sha256 local_key_spki_sha256 local_key_certificate_match "
        "served_certificate_sha256 served_intermediate_sha256 validation_boundary_sha256 "
        "validation_result activation_epoch validation_epoch rollback_state rollback_hold_until_epoch "
        "deployment_principal created_epoch expires_epoch"
    ).split()
    write_private(evidence, "".join(f"{field}={content[field]}\n" for field in fields))
    signature = evidence.with_suffix(evidence.suffix + ".sig")
    signature.unlink(missing_ok=True)
    sign(
        workspace.runner,
        workspace.env,
        workspace.requester_key,
        "platform-pki-csr-deployment-v1",
        evidence,
    )
    return evidence, signature


def publish_request(workspace: CsrWorkspace, request_id: str) -> tuple[Path, str]:
    assert_result(
        workspace.runner(
            [
                CERTIFICATE_EXPORT, "publish", "external", "--request-id",
                request_id, "--namespace", workspace.namespace,
            ],
            env=workspace.env,
            timeout=120,
        ),
        0,
    )
    artifact = workspace.pki / f"export/certificates/v1/artifacts/external/{request_id}"
    return artifact, digest(artifact / "artifact")


def decide(
    workspace: CsrWorkspace,
    request_id: str,
    artifact: Path,
    manifest_digest: str,
    *,
    action: str,
    result: str,
    predecessor_certificate_sha256: str | None = None,
    predecessor_intermediate_sha256: str | None = None,
):
    evidence, signature = write_evidence(
        workspace,
        artifact,
        action=action,
        result=result,
        request_id=request_id,
        predecessor_certificate_sha256=predecessor_certificate_sha256,
        predecessor_intermediate_sha256=predecessor_intermediate_sha256,
    )
    return run(
        workspace,
        action,
        "external",
        "--request-id",
        request_id,
        "--artifact-manifest-sha256",
        manifest_digest,
        "--evidence-file",
        evidence,
        "--evidence-signature",
        signature,
        "--yes",
    )


def test_verify_finalize_and_exact_rerun(csr_workspace: CsrWorkspace) -> None:
    artifact, manifest_digest = prepare(csr_workspace)
    verified = run(
        csr_workspace,
        "verify",
        "external",
        "--request-id",
        REQUEST_ID,
        "--format",
        "json",
    )
    assert_result(verified, 0)
    assert json.loads(verified.stdout)["state"] == "pending"
    evidence, signature = write_evidence(
        csr_workspace, artifact, action="finalize", result="activated"
    )
    arguments = (
        "finalize",
        "external",
        "--request-id",
        REQUEST_ID,
        "--artifact-manifest-sha256",
        manifest_digest,
        "--evidence-file",
        evidence,
        "--evidence-signature",
        signature,
        "--yes",
    )
    authority_before = tree_snapshot(csr_workspace.pki / "authorities")
    assert_result(run(csr_workspace, *arguments), 0)
    assert tree_snapshot(csr_workspace.pki / "authorities") == authority_before
    outcome = csr_workspace.pki / f"state/csr/outcomes/external/{REQUEST_ID}"
    assert {path.name for path in outcome.iterdir()} == {
        "deployment",
        "deployment.sig",
        "deployers.allowed_signers",
        "decision",
    }
    assert not list(outcome.rglob("*.key"))
    assert_result(run(csr_workspace, *arguments), 0)
    status = run(
        csr_workspace, "verify", "external", "--request-id", REQUEST_ID
    )
    assert_result(status, 0)
    assert "state=finalized\n" in status.stdout
    assert "accepted_evidence_state=active\n" in status.stdout

    current = artifact / "tls.crt"
    write_exchange(
        csr_workspace,
        "renew",
        "2123456789abcdef0123456789abcdef",
        "cd" * 32,
        digest(current),
    )
    assert_result(csr_workspace.sign(RENEW, current_cert=current), 0)
    write_exchange(
        csr_workspace,
        "renew",
        "3123456789abcdef0123456789abcdef",
        "de" * 32,
        digest(current),
    )
    unresolved = csr_workspace.sign(RENEW, current_cert=current)
    assert unresolved.status == 1
    assert "unresolved renewal candidate" in unresolved.stderr


def test_abandon_not_activated_is_not_active(csr_workspace: CsrWorkspace) -> None:
    artifact, manifest_digest = prepare(csr_workspace)
    evidence, signature = write_evidence(
        csr_workspace,
        artifact,
        action="abandon",
        result="not-activated",
    )
    result = run(
        csr_workspace,
        "abandon",
        "external",
        "--request-id",
        REQUEST_ID,
        "--artifact-manifest-sha256",
        manifest_digest,
        "--evidence-file",
        evidence,
        "--evidence-signature",
        signature,
        "--yes",
    )
    assert_result(result, 0)
    assert not (csr_workspace.pki / "state/csr/active/external").exists()
    assert "without revocation" in result.stdout


def test_abandoned_exact_rerun_authenticates_every_decision_field(
    csr_workspace: CsrWorkspace,
) -> None:
    artifact, manifest_digest = prepare(csr_workspace)
    evidence, signature = write_evidence(
        csr_workspace,
        artifact,
        action="abandon",
        result="not-activated",
    )
    arguments = (
        "abandon",
        "external",
        "--request-id",
        REQUEST_ID,
        "--artifact-manifest-sha256",
        manifest_digest,
        "--evidence-file",
        evidence,
        "--evidence-signature",
        signature,
        "--yes",
    )
    assert_result(run(csr_workspace, *arguments), 0)
    decision = (
        csr_workspace.pki / f"state/csr/outcomes/external/{REQUEST_ID}/decision"
    )
    original = decision.read_text()
    values = dict(line.split("=", 1) for line in original.splitlines())
    replacements = {
        "schema": "2",
        "state": "finalized",
        "operation": "renew",
        "predecessor_kind": "host-local",
        "predecessor_request_id": "1" * 32,
        "predecessor_certificate_sha256": "1" * 64,
        "predecessor_certificate_spki_sha256": "1" * 64,
        "predecessor_intermediate_sha256": "1" * 64,
        "predecessor_response_sha256": "1" * 64,
        "predecessor_artifact_manifest_sha256": "1" * 64,
        "predecessor_deployment_sha256": "1" * 64,
        "predecessor_decision_sha256": "1" * 64,
        "resulting_active_request_id": "1" * 32,
        "created_epoch": str(int(values["created_epoch"]) + 1),
    }
    for field, replacement in replacements.items():
        tampered = original.replace(
            f"{field}={values[field]}\n", f"{field}={replacement}\n"
        )
        assert tampered != original, field
        write_private(decision, tampered)
        before = tree_snapshot(csr_workspace.pki)

        rerun = run(csr_workspace, *arguments)
        assert rerun.status == 1, field
        assert tree_snapshot(csr_workspace.pki) == before, field

        verified = run(
            csr_workspace, "verify", "external", "--request-id", REQUEST_ID
        )
        assert verified.status == 1, field
        assert tree_snapshot(csr_workspace.pki) == before, field
        write_private(decision, original)


@pytest.mark.parametrize(
    "checkpoint", ("journal-written", "outcome-published", "active-published")
)
def test_finalize_recovery_resumes_outcome_and_active_pointer(
    csr_workspace: CsrWorkspace, checkpoint: str
) -> None:
    artifact, manifest_digest = prepare(csr_workspace)
    evidence, signature = write_evidence(
        csr_workspace, artifact, action="finalize", result="activated"
    )
    crashed = csr_workspace.runner(
        [
            CANDIDATE,
            "finalize",
            "external",
            "--request-id",
            REQUEST_ID,
            "--artifact-manifest-sha256",
            manifest_digest,
            "--evidence-file",
            evidence,
            "--evidence-signature",
            signature,
            "--yes",
            "--namespace",
            csr_workspace.namespace,
        ],
        env=environment(
            csr_workspace.env,
            PLATFORM_PKI_CANDIDATE_CRASH_AT=checkpoint,
        ),
        timeout=120,
    )
    assert crashed.status == 128 + signal.SIGKILL
    journal = csr_workspace.pki / "state/csr/finalization-recovery-journal"
    assert journal.is_file()
    blocked = run(
        csr_workspace, "verify", "external", "--request-id", REQUEST_ID
    )
    assert blocked.status == 1
    assert "finalization recovery is required" in blocked.stderr
    recovered = csr_workspace.runner(
        [RECOVER, "--namespace", csr_workspace.namespace, "--yes"],
        env=csr_workspace.env,
        timeout=120,
    )
    assert_result(recovered, 0)
    assert not journal.exists()
    assert (csr_workspace.pki / "state/csr/active/external").is_file()


def test_decision_rejects_schema_one_trust_and_nonce_mismatch(
    csr_workspace: CsrWorkspace,
) -> None:
    artifact, manifest_digest = prepare(csr_workspace)
    trust = csr_workspace.pki / "inventory/csr-trust"
    (trust / "deployers.allowed_signers").unlink()
    write_private(trust / "policy", POLICY)
    evidence, signature = write_evidence(
        csr_workspace, artifact, action="abandon", result="not-activated"
    )
    arguments = (
        "abandon", "external", "--request-id", REQUEST_ID,
        "--artifact-manifest-sha256", manifest_digest,
        "--evidence-file", evidence, "--evidence-signature", signature, "--yes",
    )
    schema_one = run(csr_workspace, *arguments)
    assert schema_one.status == 1
    assert "require CSR trust policy schema 2" in schema_one.stderr

    write_private(trust / "policy", POLICY2)
    requester = csr_workspace.requester_key.with_suffix(".pub").read_text().split()
    write_private(
        trust / "deployers.allowed_signers",
        f"host-01 {requester[0]} {requester[1]}\n",
    )
    evidence, signature = write_evidence(
        csr_workspace,
        artifact,
        action="abandon",
        result="not-activated",
        nonce="f" * 64,
    )
    nonce_mismatch = run(
        csr_workspace,
        "abandon", "external", "--request-id", REQUEST_ID,
        "--artifact-manifest-sha256", manifest_digest,
        "--evidence-file", evidence, "--evidence-signature", signature, "--yes",
    )
    assert nonce_mismatch.status == 1
    assert "nonce binding failed" in nonce_mismatch.stderr


@pytest.mark.parametrize("tamper", ("active", "outcome"))
def test_status_authenticates_active_pointer_and_immutable_outcome(
    csr_workspace: CsrWorkspace, tamper: str
) -> None:
    artifact, manifest_digest = prepare(csr_workspace)
    evidence, signature = write_evidence(
        csr_workspace, artifact, action="finalize", result="activated"
    )
    assert_result(run(
        csr_workspace,
        "finalize", "external", "--request-id", REQUEST_ID,
        "--artifact-manifest-sha256", manifest_digest,
        "--evidence-file", evidence, "--evidence-signature", signature, "--yes",
    ), 0)
    if tamper == "active":
        path = csr_workspace.pki / "state/csr/active/external"
        write_private(path, path.read_text().replace("operation=issue", "operation=renew"))
    else:
        path = csr_workspace.pki / f"state/csr/outcomes/external/{REQUEST_ID}/deployment"
        write_private(path, path.read_text().replace("validation_result=passed", "validation_result=not-run"))
    status = run(csr_workspace, "verify", "external", "--request-id", REQUEST_ID)
    assert status.status == 1
    renewal_id = "2123456789abcdef0123456789abcdef"
    current = artifact / "tls.crt"
    write_exchange(csr_workspace, "renew", renewal_id, "cd" * 32, digest(current))
    renewal = csr_workspace.sign(RENEW, current_cert=current)
    assert renewal.status == 1
    assert not (
        csr_workspace.pki / f"state/csr/candidates/external/{renewal_id}"
    ).exists()


def test_recovery_rejects_source_tampering(csr_workspace: CsrWorkspace) -> None:
    artifact, manifest_digest = prepare(csr_workspace)
    evidence, signature = write_evidence(
        csr_workspace, artifact, action="finalize", result="activated"
    )
    crashed = csr_workspace.runner(
        [
            CANDIDATE, "finalize", "external", "--request-id", REQUEST_ID,
            "--artifact-manifest-sha256", manifest_digest,
            "--evidence-file", evidence, "--evidence-signature", signature,
            "--yes", "--namespace", csr_workspace.namespace,
        ],
        env=environment(csr_workspace.env, PLATFORM_PKI_CANDIDATE_CRASH_AT="outcome-published"),
        timeout=120,
    )
    assert crashed.status == 128 + signal.SIGKILL
    source = csr_workspace.pki / f"state/csr/responses/external/{REQUEST_ID}/tls.crt"
    write_private(source, source.read_text() + "\n")
    recovered = csr_workspace.runner(
        [RECOVER, "--namespace", csr_workspace.namespace, "--yes"],
        env=csr_workspace.env,
        timeout=120,
    )
    assert recovered.status == 1
    assert "source" in recovered.stderr and "changed" in recovered.stderr


def test_renewal_finalization_authenticates_and_supersedes_predecessor(
    csr_workspace: CsrWorkspace,
) -> None:
    first_artifact, first_manifest = prepare(csr_workspace)
    assert_result(decide(
        csr_workspace,
        REQUEST_ID,
        first_artifact,
        first_manifest,
        action="finalize",
        result="activated",
    ), 0)
    renewal_id = "2123456789abcdef0123456789abcdef"
    current = first_artifact / "tls.crt"
    write_exchange(csr_workspace, "renew", renewal_id, "cd" * 32, digest(current))
    assert_result(csr_workspace.sign(RENEW, current_cert=current), 0)
    renewal_artifact, renewal_manifest = publish_request(csr_workspace, renewal_id)
    assert_result(decide(
        csr_workspace,
        renewal_id,
        renewal_artifact,
        renewal_manifest,
        action="finalize",
        result="activated",
    ), 0)
    old_status = run(
        csr_workspace, "verify", "external", "--request-id", REQUEST_ID
    )
    assert_result(old_status, 0)
    assert "accepted_evidence_state=superseded\n" in old_status.stdout
    new_status = run(
        csr_workspace, "verify", "external", "--request-id", renewal_id
    )
    assert_result(new_status, 0)
    assert "accepted_evidence_state=active\n" in new_status.stdout


def test_rolled_back_renewal_abandonment_preserves_active_predecessor(
    csr_workspace: CsrWorkspace,
) -> None:
    first_artifact, first_manifest = prepare(csr_workspace)
    assert_result(decide(
        csr_workspace,
        REQUEST_ID,
        first_artifact,
        first_manifest,
        action="finalize",
        result="activated",
    ), 0)
    renewal_id = "2123456789abcdef0123456789abcdef"
    current = first_artifact / "tls.crt"
    write_exchange(csr_workspace, "renew", renewal_id, "cd" * 32, digest(current))
    assert_result(csr_workspace.sign(RENEW, current_cert=current), 0)
    renewal_artifact, renewal_manifest = publish_request(csr_workspace, renewal_id)
    predecessor_intermediate = digest(
        csr_workspace.pki
        / "authorities/intermediates/g1-i1/certs/intermediate-ca.crt"
    )
    assert_result(decide(
        csr_workspace,
        renewal_id,
        renewal_artifact,
        renewal_manifest,
        action="abandon",
        result="rolled-back",
        predecessor_certificate_sha256=digest(current),
        predecessor_intermediate_sha256=predecessor_intermediate,
    ), 0)
    active = dict(
        line.split("=", 1)
        for line in (csr_workspace.pki / "state/csr/active/external")
        .read_text()
        .splitlines()
    )
    assert active["request_id"] == REQUEST_ID
    status = run(
        csr_workspace, "verify", "external", "--request-id", renewal_id
    )
    assert_result(status, 0)
    assert "state=abandoned\n" in status.stdout
    assert "accepted_evidence_state=inactive\n" in status.stdout


def test_migration_finalization_preserves_managed_state(
    csr_workspace: CsrWorkspace,
) -> None:
    workspace = csr_workspace
    managed_inventory = INVENTORY.replace(
        "    key_custody: host-local\n"
        "    target: host-01\n"
        "    validation_boundary_sha256: " + "0" * 64 + "\n"
        "    rollback_hold_seconds: 3600\n",
        "",
    )
    write_private(workspace.pki / "inventory/services.yml", managed_inventory)
    assert_result(
        workspace.runner(
            [
                ISSUE,
                "external",
                "--namespace",
                workspace.namespace,
                "--intermediate-pass-file",
                workspace.intermediate_pass,
            ],
            env=workspace.env,
            timeout=120,
        ),
        0,
    )
    certificate = workspace.pki / "services/external/certs/tls.crt"
    assert_result(
        workspace.runner(
            [
                ANSIBLE_EXPORT,
                "external",
                "--namespace",
                workspace.namespace,
                "--force",
            ],
            env=workspace.env,
            timeout=120,
        ),
        0,
    )
    managed_state = (
        tree_snapshot(workspace.pki / "services/external"),
        tree_snapshot(workspace.pki / "export/ansible/services/external"),
    )
    write_private(workspace.pki / "inventory/services.yml", INVENTORY)
    migration_id = "1123456789abcdef0123456789abcdef"
    write_exchange(
        workspace, "migrate", migration_id, "bc" * 32, digest(certificate)
    )
    install_deployer_trust(workspace)
    assert_result(workspace.issue(), 0)
    artifact, manifest_digest = publish_request(workspace, migration_id)
    assert_result(decide(
        workspace,
        migration_id,
        artifact,
        manifest_digest,
        action="finalize",
        result="activated",
    ), 0)
    assert (
        tree_snapshot(workspace.pki / "services/external"),
        tree_snapshot(workspace.pki / "export/ansible/services/external"),
    ) == managed_state
    status = run(
        workspace, "verify", "external", "--request-id", migration_id
    )
    assert_result(status, 0)
    assert "accepted_evidence_state=active\n" in status.stdout


def test_abandon_rejects_evidence_binding_time_and_result_mismatches(
    csr_workspace: CsrWorkspace,
) -> None:
    artifact, manifest_digest = prepare(csr_workspace)
    evidence, signature = write_evidence(
        csr_workspace,
        artifact,
        action="abandon",
        result="not-activated",
    )
    original = evidence.read_text()
    cases = {
        "request_sha256": ("request_sha256=", "f" * 64),
        "response_signature_sha256": ("response_signature_sha256=", "f" * 64),
        "candidate_sha256": ("candidate_sha256=", "f" * 64),
        "artifact_manifest_sha256": ("artifact_manifest_sha256=", "f" * 64),
        "certificate_spki_sha256": ("certificate_spki_sha256=", "f" * 64),
        "validation_boundary_sha256": ("validation_boundary_sha256=", "f" * 64),
        "deployment_principal": ("deployment_principal=", "other-host"),
        "action": ("action=", "finalize"),
        "local_key_certificate_match": ("local_key_certificate_match=", "false"),
        "served_certificate_sha256": ("served_certificate_sha256=", "f" * 64),
        "validation_result": ("validation_result=", "passed"),
        "expires_epoch": ("expires_epoch=", "1"),
    }
    for name, (prefix, replacement) in cases.items():
        changed = "\n".join(
            f"{prefix}{replacement}" if line.startswith(prefix) else line
            for line in original.splitlines()
        ) + "\n"
        write_private(evidence, changed)
        signature.unlink(missing_ok=True)
        sign(
            csr_workspace.runner,
            csr_workspace.env,
            csr_workspace.requester_key,
            "platform-pki-csr-deployment-v1",
            evidence,
        )
        result = run(
            csr_workspace,
            "abandon",
            "external",
            "--request-id",
            REQUEST_ID,
            "--artifact-manifest-sha256",
            manifest_digest,
            "--evidence-file",
            evidence,
            "--evidence-signature",
            signature,
            "--yes",
        )
        assert result.status == 1, name
        assert not (
            csr_workspace.pki / f"state/csr/outcomes/external/{REQUEST_ID}"
        ).exists(), name
