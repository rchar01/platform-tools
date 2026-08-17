from __future__ import annotations

import json
import os
import time
from collections.abc import Callable, Mapping
from pathlib import Path

import pytest

import src.platform_pki.offline_csr as offline_csr_module
from src.platform_pki.errors import ApplicationError
from src.platform_pki.parser import parse_route

from ..harness import ProcessResult
from .support import BIN, assert_result, digest, write_private
from .test_csr_candidate import prepare as prepare_candidate
from .test_csr_candidate import run as run_candidate
from .test_csr_candidate import write_evidence
from .test_csr_signing import CsrWorkspace, INVENTORY, ISSUE, write_exchange


pytestmark = pytest.mark.pki
OFFLINE = (BIN / "platform-pki", "offline-csr")
REQUEST_ID = "0123456789abcdef0123456789abcdef"
MIGRATION_REQUEST_ID = "1123456789abcdef0123456789abcdef"
RENEWAL_REQUEST_ID = "2123456789abcdef0123456789abcdef"
KEY_PASSPHRASE = "offline-key-passphrase"


@pytest.fixture
def offline_workspace(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    isolated_environment: Mapping[str, str],
    csr_workspace_seed_copy: Callable[[Path], None],
) -> CsrWorkspace:
    root = tmp_path / "workspace"
    csr_workspace_seed_copy(root)
    workspace = CsrWorkspace(
        root / "namespace",
        root / "namespace/pki",
        root / "platform-private",
        root / "artifacts",
        root / "intermediate.pass",
        root / "keys/requester",
        root / "keys/approver",
        root / "keys/response",
        root / "artifacts/tls.key",
        isolated_environment,
        process_runner,
    )
    write_exchange(workspace, "issue", REQUEST_ID, "ab" * 32, "none")
    return workspace


def request_directory(workspace: CsrWorkspace, name: str = "request") -> Path:
    directory = workspace.namespace.parent / name
    directory.mkdir(mode=0o700)
    for member in ("tls.csr", "request", "request.sig"):
        destination = directory / member
        destination.write_bytes((workspace.artifacts / member).read_bytes())
        destination.chmod(0o600)
    return directory


def encrypt_key(workspace: CsrWorkspace, key: Path) -> None:
    result = workspace.runner(
        [
            "ssh-keygen",
            "-p",
            "-q",
            "-P",
            "",
            "-N",
            KEY_PASSPHRASE,
            "-f",
            key,
        ],
        env=workspace.env,
    )
    assert_result(result, 0)


def approve(
    workspace: CsrWorkspace,
    request: Path,
    output: Path,
    *,
    yes: bool = True,
    input: str | None = None,
    pty: bool = False,
    operation: str = "issue",
    request_id: str = REQUEST_ID,
    environment: Mapping[str, str] | None = None,
    current_cert: Path | None = None,
) -> ProcessResult:
    arguments: list[object] = [
        *OFFLINE,
        "approve",
        "external",
        "--operation",
        operation,
        "--request-id",
        request_id,
        "--input-dir",
        request,
        "--approval-key",
        workspace.approver_key,
        "--output-dir",
        output,
        "--namespace",
        workspace.namespace,
    ]
    if yes:
        arguments.append("--yes")
    if current_cert is not None:
        arguments.extend(("--current-cert-file", current_cert))
    return workspace.runner(
        arguments,
        env=workspace.env if environment is None else environment,
        input=input,
        pty_mode="canonical" if pty else None,
        controlling_terminal=pty,
        timeout=120,
    )


def test_approve_publishes_exact_directory_and_authenticates_exact_retry(
    offline_workspace: CsrWorkspace,
) -> None:
    request = request_directory(offline_workspace)
    output = offline_workspace.namespace.parent / "approved exact"
    assert not (offline_workspace.pki / "state/csr").exists()

    created = approve(offline_workspace, request, output)

    assert_result(created, 0)
    result = json.loads(created.stdout)
    assert list(result) == [
        "status",
        "service",
        "request_id",
        "approval_dir",
        "approval_sha256",
    ]
    assert result == {
        "status": "created",
        "service": "external",
        "request_id": REQUEST_ID,
        "approval_dir": os.fspath(output),
        "approval_sha256": digest(output / "approval"),
    }
    assert {entry.name for entry in output.iterdir()} == {
        "tls.csr",
        "request",
        "request.sig",
        "approval",
        "approval.sig",
    }
    assert output.stat().st_mode & 0o777 == 0o700
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in output.iterdir())
    assert not (offline_workspace.pki / "state/csr").exists()

    existing = approve(offline_workspace, request, output)
    assert_result(existing, 0)
    assert json.loads(existing.stdout) == {**result, "status": "existing"}
    assert not (offline_workspace.pki / "state/csr").exists()


def test_approve_preserves_conflicting_partial_destination(
    offline_workspace: CsrWorkspace,
) -> None:
    request = request_directory(offline_workspace)
    output = offline_workspace.namespace.parent / "approved"
    output.mkdir(mode=0o700)
    sentinel = output / "approval"
    sentinel.write_bytes(b"preserve partial output\n")
    sentinel.chmod(0o600)

    result = approve(offline_workspace, request, output)

    assert result.status == 1
    assert result.stdout == ""
    assert sentinel.read_bytes() == b"preserve partial output\n"
    assert {entry.name for entry in output.iterdir()} == {"approval"}
    assert not (offline_workspace.pki / "state/csr").exists()


def test_approve_preserves_and_reports_retained_crash_stage(
    offline_workspace: CsrWorkspace,
) -> None:
    request = request_directory(offline_workspace)
    output = offline_workspace.namespace.parent / "approved"
    crashed = approve(
        offline_workspace,
        request,
        output,
        environment={
            **offline_workspace.env,
            "PLATFORM_PKI_OFFLINE_CSR_CRASH_AT": "approval-stage-created",
        },
    )
    assert crashed.status == 137
    retained = tuple(output.parent.glob(f".{output.name}.approve.*"))
    assert len(retained) == 1 and retained[0].is_dir()

    result = approve(offline_workspace, request, output)

    assert result.status == 1
    assert result.stdout == ""
    assert "Retained offline CSR approval stage requires inspection" in result.stderr
    assert retained[0].is_dir()
    assert not output.exists()
    assert not (offline_workspace.pki / "state/csr").exists()


def test_approve_rejects_authenticated_stage_replacement_before_publication(
    offline_workspace: CsrWorkspace,
    process_starter,
) -> None:
    request = request_directory(offline_workspace)
    output = offline_workspace.namespace.parent / "approved"
    marker = offline_workspace.namespace.parent / "approval-pause"
    release = offline_workspace.namespace.parent / "approval-release"
    environment = {
        **offline_workspace.env,
        "PLATFORM_PKI_OFFLINE_CSR_PAUSE_AT": "approval-validated",
        "PLATFORM_PKI_OFFLINE_CSR_PAUSE_MARKER": os.fspath(marker),
        "PLATFORM_PKI_OFFLINE_CSR_PAUSE_RELEASE": os.fspath(release),
    }
    process = process_starter(
        [
            *OFFLINE,
            "approve",
            "external",
            "--operation",
            "issue",
            "--request-id",
            REQUEST_ID,
            "--input-dir",
            request,
            "--approval-key",
            offline_workspace.approver_key,
            "--output-dir",
            output,
            "--namespace",
            offline_workspace.namespace,
            "--yes",
        ],
        env=environment,
        timeout=120,
    )
    deadline = time.monotonic() + 30
    while not marker.exists():
        observation = process.observe()
        if observation.status is not None:
            pytest.fail(f"approval exited before pause: {observation}")
        if time.monotonic() >= deadline:
            pytest.fail("approval pause marker was not observed")
        time.sleep(0.01)
    stages = tuple(output.parent.glob(f".{output.name}.approve.*"))
    assert len(stages) == 1
    approval = stages[0] / "approval"
    approval.write_bytes(approval.read_bytes() + b"changed=true\n")
    release.write_bytes(b"release\n")
    result = process.wait()

    assert result.status == 1
    assert result.stdout == ""
    assert not output.exists()
    assert stages[0].is_dir()
    assert not (offline_workspace.pki / "state/csr").exists()

def test_approval_confirmation_uses_real_tty_and_keeps_stdout_machine_only(
    offline_workspace: CsrWorkspace,
) -> None:
    request = request_directory(offline_workspace)
    output = offline_workspace.namespace.parent / "approved"

    result = approve(
        offline_workspace,
        request,
        output,
        yes=False,
        input=f"approve external {REQUEST_ID}\n",
        pty=True,
    )

    assert_result(result, 0)
    assert json.loads(result.stdout)["status"] == "created"
    assert "Authenticated offline CSR approval review:" in result.stderr
    assert f"Confirmation required: type 'approve external {REQUEST_ID}'" in result.stderr
    assert "Authenticated" not in result.stdout


def test_approve_supports_protected_key_without_polluting_stdout(
    offline_workspace: CsrWorkspace,
) -> None:
    encrypt_key(offline_workspace, offline_workspace.approver_key)
    request = request_directory(offline_workspace)

    result = approve(
        offline_workspace,
        request,
        offline_workspace.namespace.parent / "approved",
        input=(KEY_PASSPHRASE + "\n") * 4,
        pty=True,
    )

    assert_result(result, 0)
    assert json.loads(result.stdout)["status"] == "created"
    assert KEY_PASSPHRASE not in result.stdout + result.stderr
    assert "passphrase" not in result.stdout.lower()
    assert result.stderr.lower().count("passphrase") == 4


def test_protected_key_does_not_execute_inherited_askpass_without_tty(
    offline_workspace: CsrWorkspace,
) -> None:
    encrypt_key(offline_workspace, offline_workspace.approver_key)
    request = request_directory(offline_workspace)
    marker = offline_workspace.namespace.parent / "inherited-askpass-ran"
    fake = offline_workspace.namespace.parent / "inherited-askpass"
    fake.write_text(f"#!/bin/sh\ntouch {marker}\n")
    fake.chmod(0o700)
    environment = {
        **offline_workspace.env,
        "DISPLAY": "inherited",
        "SSH_ASKPASS": os.fspath(fake),
        "SSH_ASKPASS_REQUIRE": "force",
        "PLATFORM_PKI_INTERNAL_SSH_ASKPASS": "1",
    }

    result = offline_workspace.runner(
        [
            *OFFLINE,
            "approve",
            "external",
            "--operation",
            "issue",
            "--request-id",
            REQUEST_ID,
            "--input-dir",
            request,
            "--approval-key",
            offline_workspace.approver_key,
            "--output-dir",
            offline_workspace.namespace.parent / "approved",
            "--namespace",
            offline_workspace.namespace,
            "--yes",
        ],
        env=environment,
        timeout=120,
    )

    assert result.status == 1
    assert result.stdout == ""
    assert not marker.exists()
    assert not (offline_workspace.pki / "state/csr").exists()


@pytest.mark.parametrize("mutation", ("extra", "symlink", "hardlink"))
def test_approve_rejects_noncanonical_untrusted_directory_without_state_mutation(
    offline_workspace: CsrWorkspace,
    mutation: str,
) -> None:
    request = request_directory(offline_workspace)
    if mutation == "extra":
        (request / ".hidden").write_bytes(b"extra")
    elif mutation == "symlink":
        (request / "request.sig").unlink()
        (request / "request.sig").symlink_to("request")
    else:
        (request / "request.sig").unlink()
        os.link(request / "request", request / "request.sig")

    result = approve(
        offline_workspace,
        request,
        offline_workspace.namespace.parent / "approved",
    )

    assert result.status == 1
    assert result.stdout == ""
    assert not (offline_workspace.pki / "state/csr").exists()


def test_sign_rejection_precedes_journal_and_replay_mutation(
    offline_workspace: CsrWorkspace,
) -> None:
    request = request_directory(offline_workspace)
    approved = offline_workspace.namespace.parent / "approved"
    assert_result(approve(offline_workspace, request, approved), 0)

    result = offline_workspace.runner(
        [
            *OFFLINE,
            "sign",
            "external",
            "--operation",
            "issue",
            "--request-id",
            REQUEST_ID,
            "--input-dir",
            approved,
            "--response-key",
            offline_workspace.response_key,
            "--intermediate-pass-file",
            offline_workspace.intermediate_pass,
            "--namespace",
            offline_workspace.namespace,
        ],
        env=offline_workspace.env,
        timeout=120,
    )

    assert result.status == 1
    assert result.stdout == ""
    assert "Interactive confirmation requires a TTY" in result.stderr
    assert not (offline_workspace.pki / "state/csr/recovery-journal").exists()
    assert not (offline_workspace.pki / "state/csr/replay").exists()


@pytest.mark.parametrize(
    ("mutation", "expected_error"),
    (
        pytest.param(
            "inventory",
            "Service inventory identity changed",
            id="inventory",
        ),
        pytest.param(
            "ca-key",
            "Intermediate CA key identity changed",
            id="ca-key",
        ),
        pytest.param(
            "replay",
            "CSR request identity was consumed during signing review",
            id="replay",
        ),
        pytest.param(
            "transaction",
            "CSR signing transaction appeared during signing review",
            id="transaction",
        ),
    ),
)
def test_sign_rechecks_sources_and_absences_after_interactive_confirmation(
    offline_workspace: CsrWorkspace,
    process_starter,
    mutation: str,
    expected_error: str,
) -> None:
    request = request_directory(offline_workspace)
    approved = offline_workspace.namespace.parent / "approved"
    assert_result(approve(offline_workspace, request, approved), 0)
    process = process_starter(
        [
            *OFFLINE,
            "sign",
            "external",
            "--operation",
            "issue",
            "--request-id",
            REQUEST_ID,
            "--input-dir",
            approved,
            "--response-key",
            offline_workspace.response_key,
            "--intermediate-pass-file",
            offline_workspace.intermediate_pass,
            "--namespace",
            offline_workspace.namespace,
        ],
        env=offline_workspace.env,
        pty_mode="canonical",
        controlling_terminal=True,
        timeout=120,
    )
    expected = f"Confirmation required: type 'sign issue external {REQUEST_ID}'"
    deadline = time.monotonic() + 30
    while expected not in process.observe().stderr:
        observation = process.observe()
        if observation.status is not None:
            pytest.fail(f"signing exited before confirmation: {observation}")
        if time.monotonic() >= deadline:
            pytest.fail("signing confirmation was not observed")
        time.sleep(0.01)

    replay = offline_workspace.pki / f"state/csr/replay/requests/{REQUEST_ID}"
    transaction = (
        offline_workspace.pki / f"state/csr/transactions/csr-{REQUEST_ID}"
    )
    if mutation == "inventory":
        inventory = offline_workspace.pki / "inventory/services.yml"
        inventory.write_bytes(inventory.read_bytes() + b"\n")
    elif mutation == "ca-key":
        ca_key = (
            offline_workspace.pki
            / "authorities/intermediates/g1-i1/private/intermediate-ca.key"
        )
        ca_key.write_bytes(ca_key.read_bytes() + b"\n")
    elif mutation == "replay":
        replay.parent.mkdir(mode=0o700, parents=True)
        replay.write_bytes(b"competing replay\n")
        replay.chmod(0o600)
    else:
        transaction.mkdir(mode=0o700, parents=True)
    process.write(f"sign issue external {REQUEST_ID}\n")
    result = process.wait()

    assert result.status == 1
    assert result.stdout == ""
    assert expected_error in result.stderr
    assert not (offline_workspace.pki / "state/csr/recovery-journal").exists()
    if mutation == "replay":
        assert replay.read_bytes() == b"competing replay\n"
    else:
        assert not (offline_workspace.pki / "state/csr/replay").exists()
    if mutation == "transaction":
        assert transaction.is_dir()


@pytest.mark.parametrize(
    ("mutation", "expected_error"),
    (
        pytest.param(
            "approved-source",
            "Offline CSR approved source directory changed",
            id="approved-source",
        ),
        pytest.param(
            "installed-trust",
            "Installed CSR trust directory changed during signing",
            id="installed-trust",
        ),
    ),
)
def test_sign_fails_closed_on_source_or_trust_change_after_confirmation(
    offline_workspace: CsrWorkspace,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
    expected_error: str,
) -> None:
    request = request_directory(offline_workspace)
    approved = offline_workspace.namespace.parent / "approved"
    assert_result(approve(offline_workspace, request, approved), 0)
    changed = (
        approved / "approval"
        if mutation == "approved-source"
        else offline_workspace.pki
        / "inventory/csr-trust/responses.allowed_signers"
    )
    confirm = offline_csr_module._confirm

    def confirm_then_mutate(expected: str, yes: bool) -> None:
        confirm(expected, yes)
        changed.write_bytes(changed.read_bytes() + b"\n")

    monkeypatch.setattr(offline_csr_module, "_confirm", confirm_then_mutate)
    arguments = parse_route(
        ("offline-csr", "sign"),
        (
            "external",
            "--operation",
            "issue",
            "--request-id",
            REQUEST_ID,
            "--input-dir",
            os.fspath(approved),
            "--response-key",
            os.fspath(offline_workspace.response_key),
            "--intermediate-pass-file",
            os.fspath(offline_workspace.intermediate_pass),
            "--namespace",
            os.fspath(offline_workspace.namespace),
            "--yes",
        ),
    )

    with pytest.raises(ApplicationError, match=expected_error):
        offline_csr_module.offline_csr(
            arguments,
            environment=offline_workspace.env,
        )

    assert not (offline_workspace.pki / "state/csr/recovery-journal").exists()
    assert not (offline_workspace.pki / "state/csr/replay").exists()


def test_sign_delegates_to_authoritative_writer_and_emits_frozen_json(
    offline_workspace: CsrWorkspace,
) -> None:
    request = request_directory(offline_workspace)
    approved = offline_workspace.namespace.parent / "approved"
    assert_result(approve(offline_workspace, request, approved), 0)

    result = offline_workspace.runner(
        [
            *OFFLINE,
            "sign",
            "external",
            "--operation",
            "issue",
            "--request-id",
            REQUEST_ID,
            "--input-dir",
            approved,
            "--response-key",
            offline_workspace.response_key,
            "--intermediate-pass-file",
            offline_workspace.intermediate_pass,
            "--namespace",
            offline_workspace.namespace,
            "--yes",
        ],
        env=offline_workspace.env,
        timeout=120,
    )

    assert_result(result, 0)
    parsed = json.loads(result.stdout)
    assert list(parsed) == [
        "status",
        "operation",
        "service",
        "request_id",
        "recovery_action",
    ]
    assert parsed == {
        "status": "signed",
        "operation": "issue",
        "service": "external",
        "request_id": REQUEST_ID,
        "recovery_action": "none",
    }
    assert (offline_workspace.pki / f"state/csr/responses/external/{REQUEST_ID}/response").is_file()
    assert (offline_workspace.pki / f"state/csr/candidates/external/{REQUEST_ID}/candidate").is_file()
    assert not (offline_workspace.pki / "state/csr/recovery-journal").exists()


def test_sign_treats_reviewed_media_metadata_as_untrusted(
    offline_workspace: CsrWorkspace,
) -> None:
    request = request_directory(offline_workspace)
    approved = offline_workspace.namespace.parent / "approved"
    assert_result(approve(offline_workspace, request, approved), 0)
    media = offline_workspace.namespace.parent / "media-approved"
    media.mkdir(mode=0o755)
    for member in approved.iterdir():
        destination = media / member.name
        destination.write_bytes(member.read_bytes())
        destination.chmod(0o644)

    result = offline_workspace.runner(
        [
            *OFFLINE,
            "sign",
            "external",
            "--operation",
            "issue",
            "--request-id",
            REQUEST_ID,
            "--input-dir",
            media,
            "--response-key",
            offline_workspace.response_key,
            "--intermediate-pass-file",
            offline_workspace.intermediate_pass,
            "--namespace",
            offline_workspace.namespace,
            "--yes",
        ],
        env=offline_workspace.env,
        timeout=120,
    )

    assert_result(result, 0)
    assert json.loads(result.stdout)["status"] == "signed"
    assert not (offline_workspace.pki / "state/csr/recovery-journal").exists()


def test_migration_approval_and_signing_delegate_without_replacing_managed_state(
    offline_workspace: CsrWorkspace,
) -> None:
    host_local_inventory = (
        "    key_custody: host-local\n"
        "    target: host-01\n"
        f"    validation_boundary_sha256: {'0' * 64}\n"
        "    rollback_hold_seconds: 3600\n"
    )
    managed_inventory = INVENTORY.replace(host_local_inventory, "")
    inventory = offline_workspace.pki / "inventory/services.yml"
    write_private(inventory, managed_inventory)
    managed = offline_workspace.runner(
        [
            *ISSUE,
            "external",
            "--namespace",
            offline_workspace.namespace,
            "--intermediate-pass-file",
            offline_workspace.intermediate_pass,
        ],
        env=offline_workspace.env,
        timeout=120,
    )
    assert_result(managed, 0)
    key = offline_workspace.pki / "services/external/private/tls.key"
    certificate = offline_workspace.pki / "services/external/certs/tls.crt"
    managed_bytes = (key.read_bytes(), certificate.read_bytes())
    write_private(inventory, INVENTORY)
    write_exchange(
        offline_workspace,
        "migrate",
        MIGRATION_REQUEST_ID,
        "bc" * 32,
        digest(certificate),
    )
    request = request_directory(offline_workspace)
    approved = offline_workspace.namespace.parent / "approved"
    assert_result(
        approve(
            offline_workspace,
            request,
            approved,
            operation="migrate",
            request_id=MIGRATION_REQUEST_ID,
        ),
        0,
    )

    result = offline_workspace.runner(
        [
            *OFFLINE,
            "sign",
            "external",
            "--operation",
            "migrate",
            "--request-id",
            MIGRATION_REQUEST_ID,
            "--input-dir",
            approved,
            "--response-key",
            offline_workspace.response_key,
            "--intermediate-pass-file",
            offline_workspace.intermediate_pass,
            "--namespace",
            offline_workspace.namespace,
            "--yes",
        ],
        env=offline_workspace.env,
        timeout=120,
    )

    assert_result(result, 0)
    assert json.loads(result.stdout)["operation"] == "migrate"
    assert (key.read_bytes(), certificate.read_bytes()) == managed_bytes
    assert (
        offline_workspace.pki
        / f"state/csr/candidates/external/{MIGRATION_REQUEST_ID}/candidate"
    ).is_file()


def test_renewal_approval_and_signing_delegate_with_accepted_predecessor(
    offline_workspace: CsrWorkspace,
) -> None:
    artifact, manifest_digest = prepare_candidate(offline_workspace)
    evidence, signature = write_evidence(
        offline_workspace,
        artifact,
        action="finalize",
        result="activated",
    )
    finalized = run_candidate(
        offline_workspace,
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
    assert_result(finalized, 0)
    current = artifact / "tls.crt"
    write_exchange(
        offline_workspace,
        "renew",
        RENEWAL_REQUEST_ID,
        "cd" * 32,
        digest(current),
    )
    request = request_directory(offline_workspace, "renewal-request")
    approved = offline_workspace.namespace.parent / "renewal-approved"
    assert_result(
        approve(
            offline_workspace,
            request,
            approved,
            operation="renew",
            request_id=RENEWAL_REQUEST_ID,
            current_cert=current,
        ),
        0,
    )

    signed = offline_workspace.runner(
        [
            *OFFLINE,
            "sign",
            "external",
            "--operation",
            "renew",
            "--request-id",
            RENEWAL_REQUEST_ID,
            "--input-dir",
            approved,
            "--response-key",
            offline_workspace.response_key,
            "--current-cert-file",
            current,
            "--intermediate-pass-file",
            offline_workspace.intermediate_pass,
            "--namespace",
            offline_workspace.namespace,
            "--yes",
        ],
        env=offline_workspace.env,
        timeout=120,
    )

    assert_result(signed, 0)
    assert json.loads(signed.stdout)["operation"] == "renew"
    assert (
        offline_workspace.pki
        / f"state/csr/candidates/external/{RENEWAL_REQUEST_ID}/candidate"
    ).is_file()


def test_sign_supports_protected_response_key_through_inherited_terminal(
    offline_workspace: CsrWorkspace,
) -> None:
    request = request_directory(offline_workspace)
    approved = offline_workspace.namespace.parent / "approved"
    assert_result(approve(offline_workspace, request, approved), 0)
    encrypt_key(offline_workspace, offline_workspace.response_key)

    result = offline_workspace.runner(
        [
            *OFFLINE,
            "sign",
            "external",
            "--operation",
            "issue",
            "--request-id",
            REQUEST_ID,
            "--input-dir",
            approved,
            "--response-key",
            offline_workspace.response_key,
            "--intermediate-pass-file",
            offline_workspace.intermediate_pass,
            "--namespace",
            offline_workspace.namespace,
            "--yes",
        ],
        env=offline_workspace.env,
        input=(KEY_PASSPHRASE + "\n") * 4,
        pty_mode="canonical",
        controlling_terminal=True,
        timeout=120,
    )

    assert_result(result, 0)
    assert json.loads(result.stdout)["status"] == "signed"
    assert KEY_PASSPHRASE not in result.stdout + result.stderr
    assert "passphrase" not in result.stdout.lower()
    assert result.stderr.lower().count("passphrase") == 2
    assert not (offline_workspace.pki / "state/csr/recovery-journal").exists()


def test_postcommit_failure_recovers_only_through_csr_recover(
    offline_workspace: CsrWorkspace,
) -> None:
    request = request_directory(offline_workspace)
    approved = offline_workspace.namespace.parent / "approved"
    assert_result(approve(offline_workspace, request, approved), 0)
    environment = {
        **offline_workspace.env,
        "PLATFORM_PKI_CSR_PYTHON_WRITER_FAILURE_AT": (
            "response-signature-after-mutation"
        ),
    }

    interrupted = offline_workspace.runner(
        [
            *OFFLINE,
            "sign",
            "external",
            "--operation",
            "issue",
            "--request-id",
            REQUEST_ID,
            "--input-dir",
            approved,
            "--response-key",
            offline_workspace.response_key,
            "--intermediate-pass-file",
            offline_workspace.intermediate_pass,
            "--namespace",
            offline_workspace.namespace,
            "--yes",
        ],
        env=environment,
        timeout=120,
    )

    assert interrupted.status == 1
    assert interrupted.stdout == ""
    assert (offline_workspace.pki / "state/csr/recovery-journal").is_file()

    recovered = offline_workspace.runner(
        [
            BIN / "platform-pki",
            "csr-recover",
            "--transaction",
            f"csr-{REQUEST_ID}",
            "--response-key",
            offline_workspace.response_key,
            "--namespace",
            offline_workspace.namespace,
            "--yes",
        ],
        env=offline_workspace.env,
        timeout=120,
    )

    assert_result(recovered, 0)
    assert not (offline_workspace.pki / "state/csr/recovery-journal").exists()
    assert (
        offline_workspace.pki
        / f"state/csr/responses/external/{REQUEST_ID}/response"
    ).is_file()
