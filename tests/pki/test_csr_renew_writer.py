from __future__ import annotations

import os
import re
import shutil
import signal
import sys
import time
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path

import pytest

from src.platform_pki import csr_history
from src.platform_pki.inventory import parse_inventory

from .support import BIN, assert_result, digest, environment, write_private
from .migration_harness import run_differential_case
from .test_csr_candidate import (
    REQUEST_ID,
    decide,
    install_deployer_trust,
    prepare,
    publish_request,
)
from .test_csr_issue_writer import (
    _copied_workspace,
    _csr_differential_content,
)
from .test_csr_signing import (
    EXPORT as ANSIBLE_EXPORT,
    INVENTORY,
    ISSUE,
    RENEW,
    CsrWorkspace,
    csr_workspace,
    sign,
    write_exchange,
)


pytestmark = pytest.mark.pki
REPOSITORY = Path(__file__).resolve().parents[2]
WRITER = REPOSITORY / "tests/pki/csr_renew_writer_driver.py"
RECOVER = BIN / "platform-pki-csr-recover"
RENEWAL_ID = "2123456789abcdef0123456789abcdef"
SECOND_RENEWAL_ID = "3123456789abcdef0123456789abcdef"
THIRD_RENEWAL_ID = "4123456789abcdef0123456789abcdef"
FOURTH_RENEWAL_ID = "5123456789abcdef0123456789abcdef"


def _renew(
    workspace: CsrWorkspace,
    current: Path,
    *,
    env: Mapping[str, str] | None = None,
):
    return workspace.runner(
        [
            sys.executable,
            WRITER,
            "external",
            "--pki-dir",
            workspace.pki,
            "--request-file",
            workspace.artifacts / "request",
            "--request-signature",
            workspace.artifacts / "request.sig",
            "--approval-file",
            workspace.artifacts / "approval",
            "--approval-signature",
            workspace.artifacts / "approval.sig",
            "--csr-file",
            workspace.artifacts / "tls.csr",
            "--response-key",
            workspace.response_key,
            "--current-cert-file",
            current,
            "--intermediate-pass-file",
            workspace.intermediate_pass,
        ],
        env=workspace.env if env is None else env,
        timeout=120,
    )


def _accepted_predecessor(workspace: CsrWorkspace) -> Path:
    artifact, manifest = prepare(workspace)
    assert_result(
        decide(
            workspace,
            REQUEST_ID,
            artifact,
            manifest,
            action="finalize",
            result="activated",
        ),
        0,
    )
    return artifact / "tls.crt"


def _pending_renewal(
    workspace: CsrWorkspace,
    current: Path,
    request_id: str = RENEWAL_ID,
    nonce: str = "cd" * 32,
) -> None:
    write_exchange(
        workspace,
        "renew",
        request_id,
        nonce,
        digest(current),
    )
    assert_result(_renew(workspace, current), 0)


def _abandoned_renewal(
    workspace: CsrWorkspace,
    current: Path,
    *,
    result: str = "not-activated",
    request_id: str = RENEWAL_ID,
    nonce: str = "cd" * 32,
) -> Path:
    _pending_renewal(workspace, current, request_id, nonce)
    artifact, manifest = publish_request(workspace, request_id)
    assert_result(
        decide(
            workspace,
            request_id,
            artifact,
            manifest,
            action="abandon",
            result=result,
            predecessor_certificate_sha256=(
                digest(current) if result == "rolled-back" else None
            ),
            predecessor_intermediate_sha256=(
                digest(
                    workspace.pki
                    / "authorities/intermediates/g1-i1/certs/intermediate-ca.crt"
                )
                if result == "rolled-back"
                else None
            ),
        ),
        0,
    )
    return workspace.pki / f"state/csr/outcomes/external/{request_id}"


def _finalized_renewal(
    workspace: CsrWorkspace,
    current: Path,
    request_id: str,
    nonce: str,
) -> Path:
    _pending_renewal(workspace, current, request_id, nonce)
    artifact, manifest = publish_request(workspace, request_id)
    assert_result(
        decide(
            workspace,
            request_id,
            artifact,
            manifest,
            action="finalize",
            result="activated",
        ),
        0,
    )
    return artifact / "tls.crt"


def _decided_nonrenewal(
    workspace: CsrWorkspace,
    operation: str,
    current_certificate_sha256: str,
    request_id: str,
    nonce: str,
    *,
    action: str,
) -> Path:
    write_exchange(
        workspace,
        operation,
        request_id,
        nonce,
        current_certificate_sha256,
    )
    assert_result(workspace.issue(), 0)
    artifact, manifest = publish_request(workspace, request_id)
    assert_result(
        decide(
            workspace,
            request_id,
            artifact,
            manifest,
            action=action,
            result="activated" if action == "finalize" else "not-activated",
        ),
        0,
    )
    return artifact


def _attempt_next_renewal(workspace: CsrWorkspace, current: Path):
    write_exchange(
        workspace,
        "renew",
        SECOND_RENEWAL_ID,
        "de" * 32,
        digest(current),
    )
    return _renew(workspace, current)


def _assert_request_unconsumed(workspace: CsrWorkspace, request_id: str) -> None:
    assert not (
        workspace.pki / f"state/csr/replay/requests/{request_id}"
    ).exists()
    assert not (
        workspace.pki / f"state/csr/candidates/external/{request_id}"
    ).exists()


def _assert_next_request_unconsumed(workspace: CsrWorkspace) -> None:
    _assert_request_unconsumed(workspace, SECOND_RENEWAL_ID)


def _replace_record_fields(path: Path, values: Mapping[str, str]) -> None:
    content = path.read_text()
    for field, value in values.items():
        content, count = re.subn(
            rf"(?m)^{re.escape(field)}=[^\n]+$", f"{field}={value}", content
        )
        assert count == 1
    write_private(path, content)


def test_python_host_local_renew_authenticates_predecessor_and_publishes_candidate(
    csr_workspace: CsrWorkspace,
) -> None:
    current = _accepted_predecessor(csr_workspace)
    write_exchange(
        csr_workspace,
        "renew",
        RENEWAL_ID,
        "cd" * 32,
        digest(current),
    )

    result = _renew(csr_workspace, current)

    assert_result(result, 0)
    candidate = csr_workspace.pki / f"state/csr/candidates/external/{RENEWAL_ID}"
    response = csr_workspace.pki / f"state/csr/responses/external/{RENEWAL_ID}"
    assert candidate.is_dir() and response.is_dir()
    assert "operation=renew\n" in (response / "response").read_text()
    assert not (csr_workspace.pki / "state/csr/recovery-journal").exists()
    assert (
        csr_workspace.pki / f"state/csr/replay/requests/{RENEWAL_ID}"
    ).is_file()

    renewal_artifact, renewal_manifest = publish_request(
        csr_workspace, RENEWAL_ID
    )
    assert_result(
        decide(
            csr_workspace,
            RENEWAL_ID,
            renewal_artifact,
            renewal_manifest,
            action="finalize",
            result="activated",
        ),
        0,
    )
    next_current = renewal_artifact / "tls.crt"
    write_exchange(
        csr_workspace,
        "renew",
        SECOND_RENEWAL_ID,
        "de" * 32,
        digest(next_current),
    )
    assert_result(_renew(csr_workspace, next_current), 0)
    assert (
        csr_workspace.pki
        / f"state/csr/candidates/external/{SECOND_RENEWAL_ID}"
    ).is_dir()
    write_exchange(
        csr_workspace,
        "renew",
        THIRD_RENEWAL_ID,
        "ef" * 32,
        digest(next_current),
    )
    unresolved = _renew(csr_workspace, next_current)
    assert unresolved.status == 1
    assert "Retained CSR candidate is pending" in unresolved.stderr
    assert not (
        csr_workspace.pki / f"state/csr/replay/requests/{THIRD_RENEWAL_ID}"
    ).exists()


def test_python_host_local_renew_rejects_pending_candidate_for_different_predecessor(
    csr_workspace: CsrWorkspace,
) -> None:
    first = _accepted_predecessor(csr_workspace)
    _pending_renewal(csr_workspace, first)
    pending = (
        csr_workspace.pki / f"state/csr/candidates/external/{RENEWAL_ID}"
    )
    held = csr_workspace.artifacts / "held-pending-candidate"
    pending.rename(held)
    current = _finalized_renewal(
        csr_workspace,
        first,
        SECOND_RENEWAL_ID,
        "de" * 32,
    )
    held.rename(pending)
    write_exchange(
        csr_workspace,
        "renew",
        THIRD_RENEWAL_ID,
        "ef" * 32,
        digest(current),
    )

    result = _renew(csr_workspace, current)

    assert result.status == 1
    assert f"pending: external/{RENEWAL_ID}" in result.stderr
    _assert_request_unconsumed(csr_workspace, THIRD_RENEWAL_ID)


@pytest.mark.parametrize("outcome_result", ("not-activated", "rolled-back"))
def test_python_host_local_renew_accepts_terminal_candidate_for_different_predecessor(
    csr_workspace: CsrWorkspace,
    outcome_result: str,
) -> None:
    first = _accepted_predecessor(csr_workspace)
    _abandoned_renewal(csr_workspace, first, result=outcome_result)
    current = _finalized_renewal(
        csr_workspace,
        first,
        SECOND_RENEWAL_ID,
        "de" * 32,
    )
    write_exchange(
        csr_workspace,
        "renew",
        THIRD_RENEWAL_ID,
        "ef" * 32,
        digest(current),
    )

    assert_result(_renew(csr_workspace, current), 0)


def test_python_host_local_renew_accepts_multiple_mixed_terminal_histories(
    csr_workspace: CsrWorkspace,
) -> None:
    first = _accepted_predecessor(csr_workspace)
    _abandoned_renewal(csr_workspace, first)
    current = _finalized_renewal(
        csr_workspace,
        first,
        SECOND_RENEWAL_ID,
        "de" * 32,
    )
    _abandoned_renewal(
        csr_workspace,
        current,
        request_id=THIRD_RENEWAL_ID,
        nonce="ef" * 32,
    )
    write_exchange(
        csr_workspace,
        "renew",
        FOURTH_RENEWAL_ID,
        "fa" * 32,
        digest(current),
    )

    assert_result(_renew(csr_workspace, current), 0)


def test_python_host_local_renew_rejects_authenticated_abandoned_issue_without_active_result(
    csr_workspace: CsrWorkspace,
) -> None:
    install_deployer_trust(csr_workspace)
    _decided_nonrenewal(
        csr_workspace,
        "issue",
        "none",
        REQUEST_ID,
        "ab" * 32,
        action="abandon",
    )
    current_artifact = _decided_nonrenewal(
        csr_workspace,
        "issue",
        "none",
        RENEWAL_ID,
        "cd" * 32,
        action="finalize",
    )
    current = current_artifact / "tls.crt"
    write_exchange(
        csr_workspace,
        "renew",
        SECOND_RENEWAL_ID,
        "de" * 32,
        digest(current),
    )

    result = _renew(csr_workspace, current)

    assert result.status == 1
    assert (
        f"terminal outcome conflicts with active history: external/{REQUEST_ID}"
        in result.stderr
    )
    _assert_next_request_unconsumed(csr_workspace)


def test_python_host_local_renew_rejects_authenticated_abandoned_migration_without_active_result(
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
    managed_certificate = workspace.pki / "services/external/certs/tls.crt"
    write_private(workspace.pki / "inventory/services.yml", INVENTORY)
    install_deployer_trust(workspace)
    _decided_nonrenewal(
        workspace,
        "migrate",
        digest(managed_certificate),
        RENEWAL_ID,
        "cd" * 32,
        action="abandon",
    )
    current_artifact = _decided_nonrenewal(
        workspace,
        "migrate",
        digest(managed_certificate),
        SECOND_RENEWAL_ID,
        "de" * 32,
        action="finalize",
    )
    current = current_artifact / "tls.crt"
    write_exchange(
        workspace,
        "renew",
        THIRD_RENEWAL_ID,
        "ef" * 32,
        digest(current),
    )

    result = _renew(workspace, current)

    assert result.status == 1
    assert (
        f"terminal outcome conflicts with active history: external/{RENEWAL_ID}"
        in result.stderr
    )
    _assert_request_unconsumed(workspace, THIRD_RENEWAL_ID)


def test_python_host_local_renew_rejects_malformed_extra_outcome_before_replay(
    csr_workspace: CsrWorkspace,
) -> None:
    current = _accepted_predecessor(csr_workspace)
    extra = (
        csr_workspace.pki
        / f"state/csr/outcomes/external/{FOURTH_RENEWAL_ID}"
    )
    extra.mkdir(mode=0o700)
    write_private(extra / "decision", "invalid\n")

    result = _attempt_next_renewal(csr_workspace, current)

    assert result.status == 1
    assert "outcome has no matching retained candidate" in result.stderr
    _assert_next_request_unconsumed(csr_workspace)


def test_python_host_local_renew_rejects_pending_candidate_for_other_service(
    csr_workspace: CsrWorkspace,
) -> None:
    current = _accepted_predecessor(csr_workspace)
    inventory = csr_workspace.pki / "inventory/services.yml"
    write_private(
        inventory,
        inventory.read_text()
        + "  other:\n"
        + "    key_custody: host-local\n"
        + "    target: host-01\n"
        + "    validation_boundary_sha256: "
        + "0" * 64
        + "\n"
        + "    rollback_hold_seconds: 3600\n"
        + "    common_name: other.example.internal\n"
        + "    dns:\n"
        + "      - other.example.internal\n",
    )
    source = (
        csr_workspace.pki / f"state/csr/candidates/external/{REQUEST_ID}"
    )
    other = csr_workspace.pki / "state/csr/candidates/other"
    other.mkdir(mode=0o700)
    shutil.copytree(source, other / FOURTH_RENEWAL_ID)
    for path in (other / FOURTH_RENEWAL_ID).rglob("*"):
        if path.is_file():
            path.chmod(0o600)
    result = _attempt_next_renewal(csr_workspace, current)

    assert result.status == 1
    assert f"pending: other/{FOURTH_RENEWAL_ID}" in result.stderr
    _assert_next_request_unconsumed(csr_workspace)


@pytest.mark.parametrize("outcome_result", ("not-activated", "rolled-back"))
def test_python_host_local_renew_skips_exact_authenticated_terminal_outcome(
    csr_workspace: CsrWorkspace,
    outcome_result: str,
) -> None:
    current = _accepted_predecessor(csr_workspace)
    _abandoned_renewal(csr_workspace, current, result=outcome_result)

    result = _attempt_next_renewal(csr_workspace, current)

    assert_result(result, 0)
    assert (
        csr_workspace.pki
        / f"state/csr/candidates/external/{SECOND_RENEWAL_ID}"
    ).is_dir()


def test_python_host_local_renew_rejects_finalized_outcome_outside_active_history(
    csr_workspace: CsrWorkspace,
) -> None:
    current = _accepted_predecessor(csr_workspace)
    active = csr_workspace.pki / "state/csr/active/external"
    predecessor_active = active.read_text()
    _pending_renewal(csr_workspace, current)
    artifact, manifest = publish_request(csr_workspace, RENEWAL_ID)
    assert_result(
        decide(
            csr_workspace,
            RENEWAL_ID,
            artifact,
            manifest,
            action="finalize",
            result="activated",
        ),
        0,
    )
    write_private(active, predecessor_active)

    result = _attempt_next_renewal(csr_workspace, current)

    assert result.status == 1
    assert "terminal outcome conflicts with active history" in result.stderr
    _assert_next_request_unconsumed(csr_workspace)


@pytest.mark.parametrize(
    "kind",
    ("empty-directory", "regular-file", "symlink", "dangling-symlink"),
)
def test_python_host_local_renew_rejects_unsafe_outcome_path_before_replay(
    csr_workspace: CsrWorkspace,
    kind: str,
) -> None:
    current = _accepted_predecessor(csr_workspace)
    _pending_renewal(csr_workspace, current)
    outcome = (
        csr_workspace.pki / f"state/csr/outcomes/external/{RENEWAL_ID}"
    )
    if kind == "empty-directory":
        outcome.mkdir(mode=0o700)
    elif kind == "regular-file":
        write_private(outcome, "invalid\n")
    elif kind == "symlink":
        outcome.symlink_to(
            csr_workspace.pki
            / f"state/csr/candidates/external/{RENEWAL_ID}",
            target_is_directory=True,
        )
    else:
        outcome.symlink_to(outcome.parent / "missing", target_is_directory=True)

    result = _attempt_next_renewal(csr_workspace, current)

    assert result.status == 1
    assert "terminal outcome is invalid" in result.stderr
    _assert_next_request_unconsumed(csr_workspace)


@pytest.mark.parametrize(
    "substitution",
    (
        "malformed",
        "duplicate-field",
        "candidate",
        "request",
        "request-signature",
        "approval-signature",
        "request-and-approval-signatures",
        "inventory",
        "deployment-signature",
        "deployment-trust",
        "decision",
        "replay",
        "response-trust",
        "response-digest",
        "artifact-conflict",
        "wrong-mode",
        "hardlink",
        "entry-symlink",
        "directory-mode",
    ),
)
def test_python_host_local_renew_authenticates_terminal_outcome_before_replay(
    csr_workspace: CsrWorkspace,
    substitution: str,
) -> None:
    current = _accepted_predecessor(csr_workspace)
    outcome = _abandoned_renewal(csr_workspace, current)
    candidate = (
        csr_workspace.pki / f"state/csr/candidates/external/{RENEWAL_ID}"
    )
    transaction = csr_workspace.pki / f"state/csr/transactions/csr-{RENEWAL_ID}"
    if substitution == "malformed":
        write_private(outcome / "decision", "invalid\n")
    elif substitution == "duplicate-field":
        write_private(
            outcome / "decision",
            (outcome / "decision").read_text().replace(
                "schema=1\n", "schema=1\nschema=1\n", 1
            ),
        )
    elif substitution == "candidate":
        write_private(
            candidate / "candidate",
            (candidate / "candidate").read_text().replace(
                "state=pending", "state=invalid"
            ),
        )
    elif substitution == "request":
        write_private(
            transaction / "request",
            (transaction / "request").read_text().replace(
                "profile=server-p384-sha384-v1", "profile=invalid"
            ),
        )
    elif substitution in {
        "request-signature",
        "approval-signature",
        "request-and-approval-signatures",
    }:
        if substitution in {"request-signature", "request-and-approval-signatures"}:
            signature = transaction / "request.sig"
            signature.unlink()
            sign(
                csr_workspace.runner,
                csr_workspace.env,
                csr_workspace.approver_key,
                "platform-pki-csr-request-v1",
                transaction / "request",
            )
        if substitution in {"approval-signature", "request-and-approval-signatures"}:
            signature = transaction / "approval.sig"
            signature.unlink()
            sign(
                csr_workspace.runner,
                csr_workspace.env,
                csr_workspace.requester_key,
                "platform-pki-csr-approval-v1",
                transaction / "approval",
            )
    elif substitution == "inventory":
        deployment = outcome / "deployment"
        write_private(
            deployment,
            deployment.read_text().replace(
                "validation_boundary_sha256=" + "0" * 64,
                "validation_boundary_sha256=" + "1" * 64,
            ),
        )
        (outcome / "deployment.sig").unlink()
        sign(
            csr_workspace.runner,
            csr_workspace.env,
            csr_workspace.requester_key,
            "platform-pki-csr-deployment-v1",
            deployment,
        )
        decision = outcome / "decision"
        values = decision.read_text()
        values = re.sub(
            r"(?m)^deployment_sha256=[0-9a-f]{64}$",
            f"deployment_sha256={digest(deployment)}",
            values,
        )
        values = re.sub(
            r"(?m)^deployment_signature_sha256=[0-9a-f]{64}$",
            f"deployment_signature_sha256={digest(outcome / 'deployment.sig')}",
            values,
        )
        write_private(decision, values)
    elif substitution == "deployment-signature":
        write_private(outcome / "deployment.sig", "invalid\n")
    elif substitution == "deployment-trust":
        response_key = csr_workspace.response_key.with_suffix(".pub").read_text().split()
        write_private(
            outcome / "deployers.allowed_signers",
            f"host-01 {response_key[0]} {response_key[1]}\n",
        )
        (outcome / "deployment.sig").unlink()
        sign(
            csr_workspace.runner,
            csr_workspace.env,
            csr_workspace.response_key,
            "platform-pki-csr-deployment-v1",
            outcome / "deployment",
        )
        _replace_record_fields(
            outcome / "decision",
            {
                "deployment_signature_sha256": digest(outcome / "deployment.sig"),
                "deployers_sha256": digest(outcome / "deployers.allowed_signers"),
            },
        )
    elif substitution == "decision":
        write_private(
            outcome / "decision",
            (outcome / "decision").read_text().replace(
                "action=abandon", "action=finalize"
            ),
        )
    elif substitution == "replay":
        replay = csr_workspace.pki / f"state/csr/replay/requests/{RENEWAL_ID}"
        write_private(
            replay,
            replay.read_text().replace("target=host-01", "target=host-02"),
        )
    elif substitution == "response-trust":
        trust = transaction / "responses.allowed_signers"
        requester_key = csr_workspace.requester_key.with_suffix(".pub").read_text().split()
        write_private(
            trust,
            f"offline-response {requester_key[0]} {requester_key[1]}\n",
        )
        candidate_signature = candidate / "response.sig"
        candidate_signature.unlink()
        sign(
            csr_workspace.runner,
            csr_workspace.env,
            csr_workspace.requester_key,
            "platform-pki-csr-response-v1",
            candidate / "response",
        )
        signature = candidate_signature.read_bytes()
        response_tree = (
            csr_workspace.pki / f"state/csr/responses/external/{RENEWAL_ID}"
        )
        artifact_tree = (
            csr_workspace.pki
            / f"export/certificates/v1/artifacts/external/{RENEWAL_ID}"
        )
        for path in (
            response_tree / "response.sig",
            artifact_tree / "response.sig",
        ):
            path.write_bytes(signature)
            path.chmod(0o600)
        signature_sha = digest(candidate_signature)
        _replace_record_fields(
            candidate / "candidate",
            {"response_signature_sha256": signature_sha},
        )
        _replace_record_fields(
            artifact_tree / "artifact",
            {"source_response_signature_sha256": signature_sha},
        )
        _replace_record_fields(
            outcome / "deployment",
            {
                "response_signature_sha256": signature_sha,
                "candidate_sha256": digest(candidate / "candidate"),
                "artifact_manifest_sha256": digest(artifact_tree / "artifact"),
            },
        )
        (outcome / "deployment.sig").unlink()
        sign(
            csr_workspace.runner,
            csr_workspace.env,
            csr_workspace.requester_key,
            "platform-pki-csr-deployment-v1",
            outcome / "deployment",
        )
        _replace_record_fields(
            outcome / "decision",
            {
                "response_signature_sha256": signature_sha,
                "candidate_sha256": digest(candidate / "candidate"),
                "artifact_manifest_sha256": digest(artifact_tree / "artifact"),
                "deployment_sha256": digest(outcome / "deployment"),
                "deployment_signature_sha256": digest(outcome / "deployment.sig"),
            },
        )
    elif substitution == "response-digest":
        for response in (
            candidate / "response",
            csr_workspace.pki
            / f"state/csr/responses/external/{RENEWAL_ID}/response",
            csr_workspace.pki
            / f"export/certificates/v1/artifacts/external/{RENEWAL_ID}/response",
        ):
            write_private(
                response,
                response.read_text().replace(
                    "candidate_state=pending", "candidate_state=invalid"
                ),
            )
    elif substitution == "artifact-conflict":
        artifact_response = (
            csr_workspace.pki
            / f"export/certificates/v1/artifacts/external/{RENEWAL_ID}/response"
        )
        write_private(
            artifact_response,
            artifact_response.read_text().replace(
                "candidate_state=pending", "candidate_state=invalid"
            ),
        )
    elif substitution == "wrong-mode":
        (outcome / "decision").chmod(0o644)
    elif substitution == "hardlink":
        os.link(outcome / "decision", csr_workspace.artifacts / "decision.link")
    elif substitution == "entry-symlink":
        decision = outcome / "decision"
        backup = csr_workspace.artifacts / "decision.backup"
        decision.rename(backup)
        decision.symlink_to(backup)
    else:
        outcome.chmod(0o755)

    result = _attempt_next_renewal(csr_workspace, current)

    assert result.status == 1
    assert "terminal outcome is invalid" in result.stderr
    if substitution == "response-trust":
        assert "response trust does not match installed schema-2 CSR trust" in result.stderr
    elif substitution == "deployment-trust":
        assert "deployer trust does not match installed schema-2 CSR trust" in result.stderr
    elif substitution in {"request-signature", "request-and-approval-signatures"}:
        assert "Retained CSR request signature verification failed" in result.stderr
    elif substitution == "approval-signature":
        assert "Retained CSR approval signature verification failed" in result.stderr
    _assert_next_request_unconsumed(csr_workspace)


@pytest.mark.parametrize(
    ("checkpoint", "replay_reserved"),
    (
        ("source-before-journal-recheck", False),
        ("source-before-ca-publication", True),
    ),
)
def test_python_host_local_renew_rechecks_terminal_outcome_at_source_boundaries(
    csr_workspace: CsrWorkspace,
    process_starter,
    checkpoint: str,
    replay_reserved: bool,
) -> None:
    current = _accepted_predecessor(csr_workspace)
    outcome = _abandoned_renewal(csr_workspace, current)
    write_exchange(
        csr_workspace,
        "renew",
        SECOND_RENEWAL_ID,
        "de" * 32,
        digest(current),
    )
    marker = csr_workspace.artifacts / f"{checkpoint}.pause"
    release = csr_workspace.artifacts / f"{checkpoint}.release"
    process = process_starter(
        [
            sys.executable,
            WRITER,
            "external",
            "--pki-dir",
            csr_workspace.pki,
            "--request-file",
            csr_workspace.artifacts / "request",
            "--request-signature",
            csr_workspace.artifacts / "request.sig",
            "--approval-file",
            csr_workspace.artifacts / "approval",
            "--approval-signature",
            csr_workspace.artifacts / "approval.sig",
            "--csr-file",
            csr_workspace.artifacts / "tls.csr",
            "--response-key",
            csr_workspace.response_key,
            "--current-cert-file",
            current,
            "--intermediate-pass-file",
            csr_workspace.intermediate_pass,
        ],
        env=environment(
            csr_workspace.env,
            PLATFORM_PKI_CSR_PYTHON_WRITER_PAUSE_AT=checkpoint,
            PLATFORM_PKI_CSR_PYTHON_WRITER_PAUSE_MARKER=os.fspath(marker),
            PLATFORM_PKI_CSR_PYTHON_WRITER_PAUSE_RELEASE=os.fspath(release),
        ),
        timeout=120,
    )
    with process:
        deadline = time.monotonic() + 30
        while not marker.exists():
            observation = process.observe()
            if observation.status is not None:
                pytest.fail(f"process exited before history pause: {observation}")
            if time.monotonic() >= deadline:
                pytest.fail("timed out waiting for history pause")
            time.sleep(0.01)
        decision = outcome / "decision"
        write_private(decision, decision.read_text())
        release.touch(mode=0o600)
        result = process.wait()

    assert result.status == 1
    assert "terminal outcome changed" in result.stderr
    replay = csr_workspace.pki / f"state/csr/replay/requests/{SECOND_RENEWAL_ID}"
    assert replay.exists() is replay_reserved
    assert not (
        csr_workspace.pki / f"state/csr/candidates/external/{SECOND_RENEWAL_ID}"
    ).exists()


def test_python_host_local_renew_rejects_historical_cycle_before_replay(
    csr_workspace: CsrWorkspace,
) -> None:
    current = _accepted_predecessor(csr_workspace)
    _pending_renewal(csr_workspace, current)
    artifact, manifest = publish_request(csr_workspace, RENEWAL_ID)
    assert_result(
        decide(
            csr_workspace,
            RENEWAL_ID,
            artifact,
            manifest,
            action="finalize",
            result="activated",
        ),
        0,
    )
    decision = (
        csr_workspace.pki
        / f"state/csr/outcomes/external/{RENEWAL_ID}/decision"
    )
    write_private(
        decision,
        decision.read_text().replace(
            f"predecessor_request_id={REQUEST_ID}",
            f"predecessor_request_id={RENEWAL_ID}",
        ),
    )
    active = csr_workspace.pki / "state/csr/active/external"
    write_private(
        active,
        re.sub(
            r"(?m)^decision_sha256=[0-9a-f]{64}$",
            f"decision_sha256={digest(decision)}",
            active.read_text(),
        ),
    )
    next_current = artifact / "tls.crt"
    write_exchange(
        csr_workspace,
        "renew",
        SECOND_RENEWAL_ID,
        "de" * 32,
        digest(next_current),
    )

    result = _renew(csr_workspace, next_current)

    assert result.status == 1
    assert "predecessor chain contains a cycle" in result.stderr
    _assert_next_request_unconsumed(csr_workspace)


def test_python_host_local_renew_rejects_existing_current_candidate_before_replay(
    csr_workspace: CsrWorkspace,
) -> None:
    current = _accepted_predecessor(csr_workspace)
    write_exchange(
        csr_workspace,
        "renew",
        SECOND_RENEWAL_ID,
        "de" * 32,
        digest(current),
    )
    existing = (
        csr_workspace.pki
        / f"state/csr/candidates/external/{SECOND_RENEWAL_ID}"
    )
    existing.mkdir(mode=0o700)

    result = _renew(csr_workspace, current)

    assert result.status == 1
    assert "candidate path already exists before replay reservation" in result.stderr
    assert not (
        csr_workspace.pki / f"state/csr/replay/requests/{SECOND_RENEWAL_ID}"
    ).exists()
    assert existing.is_dir()


def test_python_host_local_renew_rejects_recovery_required_before_replay(
    csr_workspace: CsrWorkspace,
) -> None:
    current = _accepted_predecessor(csr_workspace)
    write_private(
        csr_workspace.pki / "state/csr/finalization-recovery-journal",
        "operation=csr-finalize\n",
    )
    write_exchange(
        csr_workspace,
        "renew",
        SECOND_RENEWAL_ID,
        "de" * 32,
        digest(current),
    )

    result = _renew(csr_workspace, current)

    assert result.status == 1
    assert "finalization recovery must be completed first" in result.stderr
    assert not (
        csr_workspace.pki / f"state/csr/replay/requests/{SECOND_RENEWAL_ID}"
    ).exists()


def test_python_host_local_history_has_a_recursion_depth_bound(
    csr_workspace: CsrWorkspace,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current = _accepted_predecessor(csr_workspace)
    inventory = parse_inventory(
        (csr_workspace.pki / "inventory/services.yml").read_bytes()
    )
    service = next(item for item in inventory.services if item.name == "external")
    monkeypatch.setattr(csr_history, "_MAX_HISTORY_DEPTH", 0)

    with pytest.raises(csr_history.CsrHistoryError, match="predecessor chain is too deep"):
        csr_history.authenticate_active_predecessor(
            os.fspath(csr_workspace.pki),
            service,
            digest(current),
            os.fspath(current),
            csr_workspace.env,
        )


def test_python_host_local_history_validates_current_inventory_profile(
    csr_workspace: CsrWorkspace,
) -> None:
    current = _accepted_predecessor(csr_workspace)
    inventory = parse_inventory(
        (csr_workspace.pki / "inventory/services.yml").read_bytes()
    )
    service = next(item for item in inventory.services if item.name == "external")

    with pytest.raises(
        csr_history.CsrHistoryError,
        match="certificate identity does not match inventory",
    ):
        csr_history.authenticate_active_predecessor(
            os.fspath(csr_workspace.pki),
            replace(service, common_name="other.example.internal"),
            digest(current),
            os.fspath(current),
            csr_workspace.env,
        )


def test_python_host_local_history_authenticates_current_without_external_certificate(
    csr_workspace: CsrWorkspace,
) -> None:
    _accepted_predecessor(csr_workspace)
    inventory = parse_inventory(
        (csr_workspace.pki / "inventory/services.yml").read_bytes()
    )
    service = next(item for item in inventory.services if item.name == "external")

    history = csr_history.authenticate_current_history(
        os.fspath(csr_workspace.pki),
        service,
        csr_workspace.env,
    )

    assert history.root_request_id == REQUEST_ID
    assert history.request_ids == frozenset((REQUEST_ID,))


def test_bash_python_host_local_renewal_protocol_is_equivalent(
    tmp_path: Path,
    csr_workspace: CsrWorkspace,
    process_runner,
    isolated_environment,
) -> None:
    _accepted_predecessor(csr_workspace)
    seed = csr_workspace.namespace.parent
    fixed = int(time.time())

    def copied(root: Path, env: Mapping[str, str]) -> CsrWorkspace:
        return _copied_workspace(root, env, process_runner)

    def prepare(root: Path, env: Mapping[str, str]) -> None:
        value = copied(root, env)
        predecessor = (
            value.pki
            / f"export/certificates/v1/artifacts/external/{REQUEST_ID}/tls.crt"
        )
        write_exchange(
            value,
            "renew",
            RENEWAL_ID,
            "cd" * 32,
            digest(predecessor),
            request_created=fixed - 60,
            request_expires=fixed + 3600,
            approval_created=fixed - 30,
            approval_expires=fixed + 3600,
        )

    def arguments(root: Path, tool: Path) -> tuple[str | os.PathLike[str], ...]:
        value = copied(root, {})
        predecessor = (
            value.pki
            / f"export/certificates/v1/artifacts/external/{REQUEST_ID}/tls.crt"
        )
        return (
            tool,
            "external",
            "--namespace" if tool == RENEW else "--pki-dir",
            value.namespace if tool == RENEW else value.pki,
            "--request-file",
            value.artifacts / "request",
            "--request-signature",
            value.artifacts / "request.sig",
            "--approval-file",
            value.artifacts / "approval",
            "--approval-signature",
            value.artifacts / "approval.sig",
            "--csr-file",
            value.artifacts / "tls.csr",
            "--response-key",
            value.response_key,
            "--current-cert-file",
            predecessor,
            "--intermediate-pass-file",
            value.intermediate_pass,
        )

    def bash_argv(root: Path) -> tuple[str | os.PathLike[str], ...]:
        return arguments(root, RENEW)

    def python_argv(root: Path) -> tuple[str | os.PathLike[str], ...]:
        return (sys.executable, *arguments(root, WRITER))

    def normalize_output(root: Path, value: str) -> str:
        normalized = value.replace(os.fspath(root), "<WORKSPACE>")
        normalized = re.sub(
            r"(?m)^Signing file .*\nWrite signature to .*\n", "", normalized
        )
        return re.sub(
            r"(?m)^Certificate is to be certified until .* \(([0-9]+ days)\)$",
            r"Certificate is to be certified until <NOT-AFTER> (\1)",
            normalized,
        )

    result = run_differential_case(
        seed,
        tmp_path / "differential",
        Path("namespace/pki"),
        bash_argv,
        python_argv,
        dict(
            isolated_environment,
            PLATFORM_TOOLS_LIB_DIR=os.fspath(REPOSITORY / "lib"),
        ),
        output_normalizers=(normalize_output,),
        content_normalizers=(_csr_differential_content,),
        run_options={"timeout": 120},
        bash_prepare=prepare,
        python_prepare=prepare,
        runner=process_runner,
    )

    result.assert_equivalent()


def test_python_host_local_renewal_hard_crash_uses_public_csr_recovery(
    csr_workspace: CsrWorkspace,
) -> None:
    current = _accepted_predecessor(csr_workspace)
    write_exchange(
        csr_workspace,
        "renew",
        RENEWAL_ID,
        "cd" * 32,
        digest(current),
    )
    crashed = _renew(
        csr_workspace,
        current,
        env=dict(
            csr_workspace.env,
            PLATFORM_PKI_CSR_PYTHON_WRITER_CRASH_AT="after-journal",
        ),
    )
    assert crashed.status == 128 + signal.SIGKILL, crashed

    recovered = csr_workspace.runner(
        [
            RECOVER,
            "--namespace",
            csr_workspace.namespace,
            "--transaction",
            f"csr-{RENEWAL_ID}",
            "--yes",
        ],
        env=csr_workspace.env,
        timeout=120,
    )

    assert_result(recovered, 0)
    assert not (csr_workspace.pki / "state/csr/recovery-journal").exists()
    assert not (
        csr_workspace.pki / f"state/csr/candidates/external/{RENEWAL_ID}"
    ).exists()
    assert (
        csr_workspace.pki / f"state/csr/replay/requests/{RENEWAL_ID}"
    ).is_file()
    assert (
        csr_workspace.pki
        / f"state/csr/transactions/csr-{RENEWAL_ID}/terminal"
    ).is_file()


def test_python_host_local_renew_rejects_tampered_authenticated_outcome(
    csr_workspace: CsrWorkspace,
) -> None:
    current = _accepted_predecessor(csr_workspace)
    deployment = (
        csr_workspace.pki
        / f"state/csr/outcomes/external/{REQUEST_ID}/deployment"
    )
    write_private(
        deployment,
        deployment.read_text().replace(
            "validation_result=passed", "validation_result=not-run"
        ),
    )
    write_exchange(
        csr_workspace,
        "renew",
        RENEWAL_ID,
        "cd" * 32,
        digest(current),
    )

    result = _renew(csr_workspace, current)

    assert result.status == 1
    assert "signature verification failed" in result.stderr
    assert not (
        csr_workspace.pki / f"state/csr/replay/requests/{RENEWAL_ID}"
    ).exists()
    assert not (
        csr_workspace.pki / f"state/csr/candidates/external/{RENEWAL_ID}"
    ).exists()


def test_python_host_local_renew_authenticates_managed_migration_predecessor(
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
    managed_certificate = workspace.pki / "services/external/certs/tls.crt"
    write_private(workspace.pki / "inventory/services.yml", INVENTORY)
    migration_id = "1123456789abcdef0123456789abcdef"
    write_exchange(
        workspace,
        "migrate",
        migration_id,
        "bc" * 32,
        digest(managed_certificate),
    )
    install_deployer_trust(workspace)
    assert_result(workspace.issue(), 0)
    migration_artifact, migration_manifest = publish_request(
        workspace, migration_id
    )
    assert_result(
        decide(
            workspace,
            migration_id,
            migration_artifact,
            migration_manifest,
            action="finalize",
            result="activated",
        ),
        0,
    )
    current = migration_artifact / "tls.crt"
    write_exchange(
        workspace,
        "renew",
        RENEWAL_ID,
        "cd" * 32,
        digest(current),
    )

    assert_result(_renew(workspace, current), 0)
    managed_chain = workspace.pki / "services/external/chain/ca-chain.crt"
    write_private(managed_chain, managed_chain.read_text() + "invalid\n")
    write_exchange(
        workspace,
        "renew",
        SECOND_RENEWAL_ID,
        "de" * 32,
        digest(current),
    )

    changed = _renew(workspace, current)

    assert changed.status == 1
    assert (
        "managed migration predecessor chain does not match its issuer"
        in changed.stderr.lower()
    )
    _assert_next_request_unconsumed(workspace)
