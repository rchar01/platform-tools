from __future__ import annotations

import os
import re
import shutil
import signal
import stat
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

import pytest

from src.platform_pki.filesystem import identity_from_stat
from src.platform_pki.operational import require_no_unresolved_state

from ..harness import ManagedProcess, ProcessResult
from .migration_harness import managed_openssl_dir_normalizer, snapshot_state
from .support import (
    BIN,
    assert_result,
    digest,
    environment,
    executable,
    executable_directory,
    write_executable,
    write_private,
)


pytestmark = pytest.mark.pki
INIT = BIN / "platform-pki-init"
ROOT = BIN / "platform-pki-root-create"
INTERMEDIATE = BIN / "platform-pki-intermediate-create"
TRUST_INSTALL = BIN / "platform-pki-csr-trust-install"
ISSUE = BIN / "platform-pki-service-issue"
RECOVER = BIN / "platform-pki-csr-recover"
RENEW = BIN / "platform-pki-service-renew"
EXPORT = BIN / "platform-pki-export-ansible"
INVENTORY = """services:
  external:
    key_custody: host-local
    target: host-01
    validation_boundary_sha256: 0000000000000000000000000000000000000000000000000000000000000000
    rollback_hold_seconds: 3600
    common_name: external.example.internal
    dns:
      - external.example.internal
      - external
    ips:
      - 192.0.2.50
    days: 35
"""
POLICY = """schema=1
request_namespace=platform-pki-csr-request-v1
approval_namespace=platform-pki-csr-approval-v1
response_namespace=platform-pki-csr-response-v1
request_max_age_seconds=604800
sole_operator_min_delay_seconds=86400
approval_max_age_seconds=86400
clock_skew_seconds=300
approver_principal=offline-approver
response_principal=offline-response
"""


@dataclass(frozen=True)
class CsrWorkspace:
    namespace: Path
    pki: Path
    private: Path
    artifacts: Path
    intermediate_pass: Path
    requester_key: Path
    approver_key: Path
    response_key: Path
    host_key: Path
    env: Mapping[str, str]
    runner: Callable[..., ProcessResult]

    def sign(self, tool: Path = ISSUE, *, current_cert: Path | None = None, env: Mapping[str, str] | None = None) -> ProcessResult:
        arguments: list[object] = [
            tool,
            "external",
            "--namespace",
            self.namespace,
            "--intermediate-pass-file",
            self.intermediate_pass,
            "--csr-file",
            self.artifacts / "tls.csr",
            "--request-file",
            self.artifacts / "request",
            "--request-signature",
            self.artifacts / "request.sig",
            "--approval-file",
            self.artifacts / "approval",
            "--approval-signature",
            self.artifacts / "approval.sig",
            "--response-key",
            self.response_key,
        ]
        if current_cert is not None:
            arguments.extend(["--current-cert-file", current_cert])
        return self.runner(
            arguments,
            env=self.env if env is None else env,
            timeout=120,
        )

    def issue(self, *, env: Mapping[str, str] | None = None) -> ProcessResult:
        return self.sign(env=env)


def run(runner, command: Sequence[object], env: Mapping[str, str], *, input: str | bytes | None = None) -> ProcessResult:
    return runner(command, env=env, input=input, timeout=120)


def wait_for_path(path: Path, process: ManagedProcess, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    while not path.exists():
        observation = process.observe()
        if observation.status is not None:
            pytest.fail(f"process exited before pause marker: {observation}")
        if time.monotonic() >= deadline:
            pytest.fail(f"timed out waiting for pause marker: {path}")
        time.sleep(0.01)


def ssh_key(runner, env: Mapping[str, str], path: Path) -> str:
    result = run(runner, ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", path], env)
    assert_result(result, 0)
    fields = path.with_suffix(".pub").read_text().split()
    return f"{fields[0]} {fields[1]}"


def sign(runner, env: Mapping[str, str], key: Path, namespace: str, path: Path) -> None:
    assert_result(run(runner, ["ssh-keygen", "-Y", "sign", "-f", key, "-n", namespace, path], env), 0)
    path.with_suffix(path.suffix + ".sig").chmod(0o600)


def spki_digest(runner, env: Mapping[str, str], kind: str, path: Path, directory: Path) -> str:
    public = directory / f"{kind}.pub.pem"
    der = directory / f"{kind}.pub.der"
    if kind == "csr":
        result = run(runner, ["openssl", "req", "-in", path, "-pubkey", "-noout"], env)
        assert_result(result, 0)
        public.write_text(result.stdout)
        result = run(runner, ["openssl", "pkey", "-pubin", "-in", public, "-outform", "DER", "-out", der], env)
    else:
        result = run(runner, ["openssl", "pkey", "-in", path, "-pubout", "-outform", "DER", "-out", der], env)
    assert_result(result, 0)
    return digest(der)


def write_exchange(
    workspace: CsrWorkspace,
    operation: str,
    request_id: str,
    nonce: str,
    current_cert_sha256: str,
    *,
    request_created: int | None = None,
    request_expires: int | None = None,
    approval_created: int | None = None,
    approval_expires: int | None = None,
) -> None:
    artifacts = workspace.artifacts
    now = int(time.time())
    request_created = now - 60 if request_created is None else request_created
    request_expires = now + 3600 if request_expires is None else request_expires
    approval_created = now - 30 if approval_created is None else approval_created
    approval_expires = now + 3600 if approval_expires is None else approval_expires
    csr_sha = digest(artifacts / "tls.csr")
    csr_spki = spki_digest(workspace.runner, workspace.env, "csr", artifacts / "tls.csr", artifacts)
    inventory_sha = digest(workspace.pki / "inventory/services.yml")
    request = f"""schema=1
request_id={request_id}
nonce={nonce}
created_epoch={request_created}
expires_epoch={request_expires}
operation={operation}
service=external
target=host-01
requester_principal=host-01
inventory_sha256={inventory_sha}
csr_sha256={csr_sha}
csr_spki_sha256={csr_spki}
current_cert_sha256={current_cert_sha256}
profile=server-p384-sha384-v1
response_principal=offline-response
"""
    write_private(artifacts / "request", request)
    (artifacts / "request.sig").unlink(missing_ok=True)
    sign(workspace.runner, workspace.env, workspace.requester_key, "platform-pki-csr-request-v1", artifacts / "request")
    approval = f"""schema=1
request_id={request_id}
nonce={nonce}
created_epoch={approval_created}
expires_epoch={approval_expires}
approver_principal=offline-approver
request_sha256={digest(artifacts / 'request')}
csr_sha256={csr_sha}
inventory_sha256={inventory_sha}
operation={operation}
service=external
target=host-01
profile=server-p384-sha384-v1
"""
    write_private(artifacts / "approval", approval)
    (artifacts / "approval.sig").unlink(missing_ok=True)
    sign(workspace.runner, workspace.env, workspace.approver_key, "platform-pki-csr-approval-v1", artifacts / "approval")


def write_csr(workspace: CsrWorkspace, *, digest_name: str = "sha384", attributes: Sequence[str] = ()) -> None:
    config = workspace.artifacts / "request.cnf"
    attribute_config = "attributes = attrs\n" if attributes else ""
    attribute_section = "[attrs]\n" + "\n".join(attributes) + "\n" if attributes else ""
    write_private(
        config,
        "[req]\n"
        "prompt = no\n"
        "distinguished_name = dn\n"
        f"{attribute_config}"
        "req_extensions = ext\n"
        "[dn]\n"
        "CN = external.example.internal\n"
        f"{attribute_section}"
        "[ext]\n"
        "subjectAltName = DNS:external.example.internal,DNS:external,IP:192.0.2.50\n",
    )
    assert_result(
        run(
            workspace.runner,
            [
                "openssl",
                "req",
                "-new",
                f"-{digest_name}",
                "-key",
                workspace.host_key,
                "-config",
                config,
                "-out",
                workspace.artifacts / "tls.csr",
            ],
            workspace.env,
        ),
        0,
    )
    (workspace.artifacts / "tls.csr").chmod(0o600)
    write_exchange(workspace, "issue", "0123456789abcdef0123456789abcdef", "ab" * 32, "none")


def tree_snapshot(root: Path) -> dict[str, tuple[int, int, int, int, str]]:
    snapshot: dict[str, tuple[int, int, int, int, str]] = {}
    for path in sorted(root.rglob("*")):
        metadata = path.lstat()
        relative = path.relative_to(root).as_posix()
        content = digest(path) if path.is_file() and not path.is_symlink() else ""
        snapshot[relative] = (
            stat.S_IFMT(metadata.st_mode) | stat.S_IMODE(metadata.st_mode),
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
            content,
        )
    return snapshot


def restorable_tree_snapshot(root: Path) -> dict[str, tuple[int, int, int, int, int, str]]:
    snapshot: dict[str, tuple[int, int, int, int, int, str]] = {}
    for path in sorted(root.rglob("*")):
        metadata = path.lstat()
        regular_file = path.is_file() and not path.is_symlink()
        snapshot[path.relative_to(root).as_posix()] = (
            stat.S_IFMT(metadata.st_mode) | stat.S_IMODE(metadata.st_mode),
            metadata.st_uid,
            metadata.st_gid,
            metadata.st_size if regular_file else 0,
            metadata.st_mtime_ns if regular_file else 0,
            digest(path) if regular_file else "",
        )
    return snapshot


def _create_csr_workspace(
    root: Path,
    runner: Callable[..., ProcessResult],
    isolated_environment: Mapping[str, str],
) -> CsrWorkspace:
    namespace = root / "namespace"
    pki = namespace / "pki"
    private = root / "platform-private"
    artifacts = root / "artifacts"
    keys = root / "keys"
    for directory in (artifacts, keys):
        directory.mkdir(mode=0o700)
    root_pass = root / "root.pass"
    intermediate_pass = root / "intermediate.pass"
    write_private(root_pass, "root-test-passphrase-123\n")
    write_private(intermediate_pass, "intermediate-test-passphrase-123\n")
    assert_result(run(runner, [INIT, "--namespace", namespace], isolated_environment), 0)
    write_private(pki / "inventory/services.yml", INVENTORY)
    assert_result(
        run(
            runner,
            [ROOT, "--namespace", namespace, "--name", "Test Root", "--org", "Test", "--country", "PL", "--root-pass-file", root_pass],
            isolated_environment,
        ),
        0,
    )
    assert_result(
        run(
            runner,
            [
                INTERMEDIATE,
                "--namespace",
                namespace,
                "--name",
                "Test Intermediate",
                "--org",
                "Test",
                "--country",
                "PL",
                "--root-pass-file",
                root_pass,
                "--intermediate-pass-file",
                intermediate_pass,
            ],
            isolated_environment,
        ),
        0,
    )
    requester_key = keys / "requester"
    approver_key = keys / "approver"
    response_key = keys / "response"
    requester_public = ssh_key(runner, isolated_environment, requester_key)
    approver_public = ssh_key(runner, isolated_environment, approver_key)
    response_public = ssh_key(runner, isolated_environment, response_key)
    trust = private / "pki/csr-trust"
    trust.mkdir(mode=0o700, parents=True)
    private.chmod(0o700)
    (private / "pki").chmod(0o700)
    write_private(trust / "policy", POLICY)
    write_private(trust / "requesters.allowed_signers", f"host-01 {requester_public}\n")
    write_private(trust / "approvers.allowed_signers", f"offline-approver {approver_public}\n")
    write_private(trust / "responses.allowed_signers", f"offline-response {response_public}\n")
    assert_result(run(runner, [TRUST_INSTALL, "--namespace", namespace, "--private-repo", private], isolated_environment), 0)
    host_key = artifacts / "tls.key"
    assert_result(
        run(runner, ["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:secp384r1", "-out", host_key], isolated_environment),
        0,
    )
    host_key.chmod(0o600)
    assert_result(
        run(
            runner,
            [
                "openssl",
                "req",
                "-new",
                "-sha384",
                "-key",
                host_key,
                "-subj",
                "/CN=external.example.internal",
                "-addext",
                "subjectAltName=DNS:external.example.internal,DNS:external,IP:192.0.2.50",
                "-out",
                artifacts / "tls.csr",
            ],
            isolated_environment,
        ),
        0,
    )
    (artifacts / "tls.csr").chmod(0o600)
    return CsrWorkspace(namespace, pki, private, artifacts, intermediate_pass, requester_key, approver_key, response_key, host_key, isolated_environment, runner)


@pytest.fixture
def csr_workspace(
    tmp_path,
    process_runner,
    isolated_environment,
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
    write_exchange(workspace, "issue", "0123456789abcdef0123456789abcdef", "ab" * 32, "none")
    return workspace


def test_csr_workspace_copies_are_isolated_and_configs_are_rebased(
    tmp_path: Path,
    csr_workspace: CsrWorkspace,
    csr_workspace_seed_copy: Callable[[Path], None],
    _csr_workspace_seed: Path,
) -> None:
    assert not (csr_workspace.pki / "state/rollover/journal").exists()
    require_no_unresolved_state(os.fspath(csr_workspace.pki))
    normalizer = managed_openssl_dir_normalizer(
        _csr_workspace_seed, csr_workspace.namespace.parent
    )
    source = tuple(
        entry
        for entry in snapshot_state(
            _csr_workspace_seed / "namespace/pki", (normalizer,)
        )
        if entry.path != "state/rollover/journal"
    )
    copied = snapshot_state(csr_workspace.pki, (normalizer,))
    assert copied == source

    (csr_workspace.pki / "authorities/intermediates/g1-i1/serial").write_text(
        "DEAD\n", encoding="utf-8"
    )

    second = tmp_path / "second-workspace"
    csr_workspace_seed_copy(second)
    seed_serial = (
        second / "namespace/pki/authorities/intermediates/g1-i1/serial"
    ).read_bytes()
    assert seed_serial != b"DEAD\n"
    for relative in (
        "namespace/pki/authorities/roots/g1/openssl.cnf",
        "namespace/pki/authorities/intermediates/g1-i1/openssl.cnf",
    ):
        content = (second / relative).read_text(encoding="utf-8")
        assert os.fspath(second) in content

    (second / "namespace/pki/authorities/intermediates/g1-i1/serial").write_text(
        "BEEF\n", encoding="utf-8"
    )
    third = tmp_path / "third-workspace"
    csr_workspace_seed_copy(third)
    assert (
        third / "namespace/pki/authorities/intermediates/g1-i1/serial"
    ).read_bytes() == seed_serial


def test_csr_seed_copy_accepts_exact_intermediate_bootstrap_transaction(
    tmp_path: Path,
    csr_workspace_seed_copy: Callable[[Path], None],
    _csr_workspace_seed_transaction: str,
) -> None:
    destination = tmp_path / "exact-transaction-copy"
    csr_workspace_seed_copy(destination)

    reservation = dict(
        line.split("=", 1)
        for line in (
            destination
            / "namespace/pki/state/generation-reservations/g1-i1"
        ).read_text(encoding="ascii").splitlines()
    )
    assert reservation["transaction"] == _csr_workspace_seed_transaction
    assert not (destination / "namespace/pki/state/rollover/journal").exists()


@pytest.mark.parametrize(
    "case",
    ("malformed", "pending", "unknown-operation", "wrong-operation", "wrong-transaction"),
)
def test_csr_seed_copy_rejects_nonterminal_or_unexpected_rollover_journal(
    tmp_path: Path,
    _csr_workspace_seed: Path,
    _csr_workspace_seed_transaction: str,
    csr_workspace_private_seed_copy: Callable[[Path], None],
    csr_workspace_seed_copy: Callable[..., None],
    case: str,
) -> None:
    shared_journal = (
        _csr_workspace_seed / "namespace/pki/state/rollover/journal"
    )
    shared_bytes = shared_journal.read_bytes()
    shared_identity = identity_from_stat(shared_journal.lstat())
    shared_state = snapshot_state(_csr_workspace_seed)
    shared_object_identities = tuple(
        (entry.path, entry.identity) for entry in shared_state
    )
    try:
        private_seed = tmp_path / "private-seed"
        csr_workspace_private_seed_copy(private_seed)
        normalizer = managed_openssl_dir_normalizer(
            _csr_workspace_seed, private_seed
        )
        assert tuple(
            entry
            for entry in snapshot_state(_csr_workspace_seed, (normalizer,))
            if entry.path != "namespace/pki/state/rollover/journal"
        ) == tuple(
            entry
            for entry in snapshot_state(private_seed, (normalizer,))
            if entry.path != "namespace/pki/state/rollover/journal"
        )

        journal = private_seed / "namespace/pki/state/rollover/journal"
        data = journal.read_bytes()
        if case == "malformed":
            data += b"malformed\n"
        elif case == "pending":
            data = data.replace(b"committed=true\n", b"committed=false\n", 1)
        elif case == "unknown-operation":
            data = data.replace(
                b"operation=intermediate-bootstrap\n", b"operation=unknown\n", 1
            )
        elif case == "wrong-operation":
            data = data.replace(
                b"operation=intermediate-bootstrap\n",
                b"operation=root-bootstrap\n",
                1,
            )
        else:
            replacement_transaction = "intermediate-bootstrap-20000101-000000-1"
            if replacement_transaction == _csr_workspace_seed_transaction:
                replacement_transaction = "intermediate-bootstrap-20000101-000000-2"
            data = re.sub(
                rb"(?m)^transaction=.*$",
                f"transaction={replacement_transaction}".encode("ascii"),
                data,
                count=1,
            )
        journal.write_bytes(data)

        destination = tmp_path / "rejected-copy"
        with pytest.raises(ValueError):
            csr_workspace_seed_copy(destination, source=private_seed)
        assert not destination.exists()
    finally:
        current_state = snapshot_state(_csr_workspace_seed)
        assert current_state == shared_state
        assert tuple(
            (entry.path, entry.identity) for entry in current_state
        ) == shared_object_identities
        assert shared_journal.read_bytes() == shared_bytes
        assert identity_from_stat(shared_journal.lstat()) == shared_identity


def test_authenticated_issue_publishes_certificate_only_candidate_and_response(csr_workspace: CsrWorkspace) -> None:
    workspace = csr_workspace
    result = workspace.issue()
    assert_result(result, 0)
    request_id = "0123456789abcdef0123456789abcdef"
    candidate = workspace.pki / f"state/csr/candidates/external/{request_id}"
    response = workspace.pki / f"state/csr/responses/external/{request_id}"
    for root in (candidate, response):
        assert sorted(path.name for path in root.iterdir()) == (
            ["ca-chain.crt", "candidate", "fullchain.crt", "response", "response.sig", "tls.crt"]
            if root == candidate
            else ["ca-chain.crt", "fullchain.crt", "response", "response.sig", "tls.crt"]
        )
        assert not list(root.rglob("*.key"))
    assert not (workspace.pki / "services/external/private/tls.key").exists()
    assert not (workspace.pki / "services/external/certs/tls.crt").exists()
    authority = workspace.pki / "authorities/intermediates/g1-i1"
    assert (authority / "serial").read_text().strip() == "1001"
    assert (authority / "newcerts/1000.pem").is_file()
    verify = run(
        workspace.runner,
        [
            "ssh-keygen",
            "-Y",
            "verify",
            "-f",
            workspace.pki / "inventory/csr-trust/responses.allowed_signers",
            "-I",
            "offline-response",
            "-n",
            "platform-pki-csr-response-v1",
            "-s",
            response / "response.sig",
        ],
        workspace.env,
        input=(response / "response").read_bytes(),
    )
    assert_result(verify, 0)
    assert spki_digest(workspace.runner, workspace.env, "key", workspace.host_key, workspace.artifacts) == spki_digest(
        workspace.runner, workspace.env, "csr", workspace.artifacts / "tls.csr", workspace.artifacts
    )
    assert not (workspace.pki / "state/csr/recovery-journal").exists()


@pytest.mark.parametrize("checkpoint", (None, "response-signed"), ids=("success", "recovery"))
def test_migration_preserves_complete_managed_service_and_export_state(csr_workspace: CsrWorkspace, checkpoint: str | None) -> None:
    workspace = csr_workspace
    managed_inventory = INVENTORY.replace(
        "    key_custody: host-local\n"
        "    target: host-01\n"
        "    validation_boundary_sha256: 0000000000000000000000000000000000000000000000000000000000000000\n"
        "    rollback_hold_seconds: 3600\n",
        "",
    )
    write_private(workspace.pki / "inventory/services.yml", managed_inventory)
    managed = run(
        workspace.runner,
        [ISSUE, "external", "--namespace", workspace.namespace, "--intermediate-pass-file", workspace.intermediate_pass],
        workspace.env,
    )
    assert_result(managed, 0)
    key = workspace.pki / "services/external/private/tls.key"
    certificate = workspace.pki / "services/external/certs/tls.crt"
    assert_result(
        run(workspace.runner, [EXPORT, "external", "--namespace", workspace.namespace, "--force"], workspace.env),
        0,
    )
    service_root = workspace.pki / "services/external"
    export_root = workspace.pki / "export/ansible/services/external"
    managed_state = (tree_snapshot(service_root), tree_snapshot(export_root))
    write_private(workspace.pki / "inventory/services.yml", INVENTORY)
    write_exchange(
        workspace,
        "migrate",
        "1123456789abcdef0123456789abcdef",
        "bc" * 32,
        digest(certificate),
    )

    sign_env = workspace.env if checkpoint is None else environment(workspace.env, PLATFORM_PKI_CSR_CRASH_AT=checkpoint)
    result = workspace.issue(env=sign_env)
    if checkpoint is not None:
        assert result.status == 128 + signal.SIGKILL
        result = run(
            workspace.runner,
            [
                RECOVER,
                "--namespace",
                workspace.namespace,
                "--transaction",
                "csr-1123456789abcdef0123456789abcdef",
                "--response-key",
                workspace.response_key,
                "--yes",
            ],
            workspace.env,
        )

    assert_result(result, 0)
    assert (tree_snapshot(service_root), tree_snapshot(export_root)) == managed_state
    candidate = workspace.pki / "state/csr/candidates/external/1123456789abcdef0123456789abcdef"
    assert candidate.is_dir()
    assert "state=pending\n" in (candidate / "candidate").read_text()


def test_host_local_renewal_requires_active_accepted_evidence(csr_workspace: CsrWorkspace) -> None:
    workspace = csr_workspace
    assert_result(workspace.issue(), 0)
    current = workspace.pki / "state/csr/candidates/external/0123456789abcdef0123456789abcdef/tls.crt"
    write_exchange(
        workspace,
        "renew",
        "2123456789abcdef0123456789abcdef",
        "cd" * 32,
        digest(current),
    )

    result = workspace.sign(RENEW, current_cert=current)

    assert result.status == 1
    assert "active accepted-evidence pointer" in result.stderr
    assert not (workspace.pki / "state/csr/candidates/external/2123456789abcdef0123456789abcdef").exists()
    assert (workspace.pki / "authorities/intermediates/g1-i1/serial").read_text().strip() == "1001"


def test_issue_rejects_renewal_only_current_certificate_input(csr_workspace: CsrWorkspace) -> None:
    workspace = csr_workspace

    result = workspace.sign(ISSUE, current_cert=workspace.artifacts / "tls.csr")

    assert result.status == 1
    assert "--current-cert-file is available only for host-local renewal" in result.stderr
    assert not (workspace.pki / "state/csr/replay/requests/0123456789abcdef0123456789abcdef").exists()


@pytest.mark.parametrize(
    ("checkpoint", "committed"),
    (
        pytest.param("after-journal", False, id="pre-commit-journal"),
        pytest.param("replay-reserved", False, id="pre-commit-replay"),
        pytest.param("transaction-staged", False, id="pre-commit-transaction"),
        pytest.param("signing-ready", False, id="pre-commit-signing-ready"),
        pytest.param("signing-complete", False, id="pre-commit-signing-complete"),
        pytest.param("sensitive-key-removed", False, id="pre-commit-key-removed"),
        pytest.param("after-ca-index-publish", False, id="pre-commit"),
        pytest.param("after-ca-index_attr-publish", False, id="pre-commit-index-attr"),
        pytest.param("after-ca-serial-publish", False, id="pre-commit-serial"),
        pytest.param("after-ca-index_old-publish", False, id="pre-commit-index-old"),
        pytest.param("after-ca-index_attr_old-publish", False, id="pre-commit-index-attr-old"),
        pytest.param("after-ca-serial_old-publish", False, id="pre-commit-serial-old"),
        pytest.param("after-ca-newcert-publish", False, id="pre-commit-newcert"),
        pytest.param("ca-committed", True, id="post-commit"),
        pytest.param("response-signed", True, id="post-commit-response-signed"),
        pytest.param("candidate-published", True, id="post-commit-candidate"),
        pytest.param("response-published", True, id="post-commit-response"),
        pytest.param("before-journal-cleanup", True, id="post-commit-terminal-cleanup"),
    ),
)
def test_interrupted_signing_has_deterministic_recovery(csr_workspace: CsrWorkspace, checkpoint: str, committed: bool) -> None:
    workspace = csr_workspace
    authority = workspace.pki / "authorities/intermediates/g1-i1"
    original_serial = (authority / "serial").read_text()
    original_ca = restorable_tree_snapshot(authority)
    crash_env = environment(workspace.env, PLATFORM_PKI_CSR_CRASH_AT=checkpoint)
    result = workspace.issue(env=crash_env)
    assert result.status == 128 + signal.SIGKILL
    journal = workspace.pki / "state/csr/recovery-journal"
    assert journal.is_file()
    assert f"committed={'true' if committed else 'false'}\n" in journal.read_text()
    committed_ca = tree_snapshot(authority) if committed else None
    issued = authority / "newcerts/1000.pem"
    issued_digest = digest(issued) if committed else None
    signature = workspace.pki / "state/csr/transactions/csr-0123456789abcdef0123456789abcdef/signing/response.sig"
    signature_state = (signature.stat().st_ino, digest(signature)) if signature.exists() else None
    command: list[object] = [RECOVER, "--namespace", workspace.namespace, "--transaction", "csr-0123456789abcdef0123456789abcdef", "--yes"]
    if committed:
        command.extend(["--response-key", workspace.response_key])
    recovered = run(workspace.runner, command, workspace.env)
    assert_result(recovered, 0)
    assert not journal.exists()
    replay = workspace.pki / "state/csr/replay/requests/0123456789abcdef0123456789abcdef"
    assert replay.is_file()
    if committed:
        assert tree_snapshot(authority) == committed_ca
        assert (authority / "serial").read_text().strip() == "1001"
        assert digest(issued) == issued_digest
        assert (workspace.pki / "state/csr/responses/external/0123456789abcdef0123456789abcdef/response.sig").is_file()
        if signature_state is not None:
            assert (signature.stat().st_ino, digest(signature)) == signature_state
    else:
        assert restorable_tree_snapshot(authority) == original_ca
        assert (authority / "serial").read_text() == original_serial
        assert not (authority / "newcerts/1000.pem").exists()
        assert not (workspace.pki / "state/csr/responses/external/0123456789abcdef0123456789abcdef").exists()
    repeated = workspace.issue()
    assert repeated.status == 1
    assert "CSR request ID has already been consumed" in repeated.stderr


def test_committed_recovery_without_response_key_stays_blocked(csr_workspace: CsrWorkspace) -> None:
    workspace = csr_workspace
    result = workspace.issue(env=environment(workspace.env, PLATFORM_PKI_CSR_CRASH_AT="ca-committed"))
    assert result.status == 128 + signal.SIGKILL
    transaction = "csr-0123456789abcdef0123456789abcdef"
    missing = run(workspace.runner, [RECOVER, "--namespace", workspace.namespace, "--transaction", transaction, "--yes"], workspace.env)
    assert missing.status == 1
    assert "requires --response-key" in missing.stderr
    assert (workspace.pki / "state/csr/recovery-journal").is_file()
    blocked = run(workspace.runner, [TRUST_INSTALL, "--namespace", workspace.namespace, "--private-repo", workspace.private], workspace.env)
    assert blocked.status == 1
    assert "Authenticated CSR signing recovery is required" in blocked.stderr
    recovered = run(
        workspace.runner,
        [RECOVER, "--namespace", workspace.namespace, "--transaction", transaction, "--response-key", workspace.response_key, "--yes"],
        workspace.env,
    )
    assert_result(recovered, 0)


def test_recovery_rejects_journal_path_outside_transaction(csr_workspace: CsrWorkspace) -> None:
    workspace = csr_workspace
    result = workspace.issue(env=environment(workspace.env, PLATFORM_PKI_CSR_CRASH_AT="signing-ready"))
    assert result.status == 128 + signal.SIGKILL
    journal = workspace.pki / "state/csr/recovery-journal"
    sentinel = workspace.artifacts / "outside-ca-state"
    write_private(sentinel, "outside sentinel\n")
    content = journal.read_text()
    content = content.replace(
        f"db_index_path={workspace.pki}/authorities/intermediates/g1-i1/index.txt\n",
        f"db_index_path={sentinel}\n",
    )
    write_private(journal, content)

    recovered = run(
        workspace.runner,
        [RECOVER, "--namespace", workspace.namespace, "--transaction", "csr-0123456789abcdef0123456789abcdef", "--yes"],
        workspace.env,
    )

    assert recovered.status == 1
    assert "CSR recovery CA path is outside the active intermediate: index" in recovered.stderr
    assert sentinel.read_text() == "outside sentinel\n"
    assert journal.is_file()


def test_recovery_rejects_replaced_sensitive_key_copy(csr_workspace: CsrWorkspace) -> None:
    workspace = csr_workspace
    result = workspace.issue(env=environment(workspace.env, PLATFORM_PKI_CSR_CRASH_AT="signing-complete"))
    assert result.status == 128 + signal.SIGKILL
    key = workspace.pki / "state/csr/transactions/csr-0123456789abcdef0123456789abcdef/signing/private/intermediate-ca.key"
    key.unlink()
    write_private(key, "replacement sentinel\n")

    recovered = run(
        workspace.runner,
        [RECOVER, "--namespace", workspace.namespace, "--transaction", "csr-0123456789abcdef0123456789abcdef", "--yes"],
        workspace.env,
    )

    assert recovered.status == 1
    assert "Journaled CSR signing key copy identity changed" in recovered.stderr
    assert key.read_text() == "replacement sentinel\n"
    assert (workspace.pki / "state/csr/recovery-journal").is_file()


def test_preexisting_transaction_tree_is_rejected_without_mutation(csr_workspace: CsrWorkspace) -> None:
    workspace = csr_workspace
    csr_state = workspace.pki / "state/csr"
    transactions = csr_state / "transactions"
    for directory in (csr_state, transactions):
        if not directory.exists():
            directory.mkdir(mode=0o700)
    transaction = transactions / "csr-0123456789abcdef0123456789abcdef"
    transaction.mkdir(mode=0o700)
    sentinel = transaction / "sentinel"
    write_private(sentinel, "pre-existing transaction must survive\n")
    metadata = sentinel.lstat()
    before = (
        transaction.stat().st_ino,
        stat.S_IMODE(metadata.st_mode),
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        digest(sentinel),
    )

    result = workspace.issue()

    metadata = sentinel.lstat()
    after = (
        transaction.stat().st_ino,
        stat.S_IMODE(metadata.st_mode),
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        digest(sentinel),
    )
    assert result.status == 1
    assert "CSR signing transaction path already exists" in result.stderr
    assert after == before
    assert not (workspace.pki / "state/csr/recovery-journal").exists()
    assert not (workspace.pki / "state/csr/replay/requests/0123456789abcdef0123456789abcdef").exists()


def test_recovery_does_not_remove_unrecorded_sensitive_key_path(csr_workspace: CsrWorkspace) -> None:
    workspace = csr_workspace
    result = workspace.issue(env=environment(workspace.env, PLATFORM_PKI_CSR_CRASH_AT="after-journal"))
    assert result.status == 128 + signal.SIGKILL
    transaction = workspace.pki / "state/csr/transactions/csr-0123456789abcdef0123456789abcdef"
    private = transaction / "signing/private"
    private.mkdir(mode=0o700, parents=True)
    for directory in (transaction, transaction / "signing", private):
        directory.chmod(0o700)
    sentinel = private / "intermediate-ca.key"
    write_private(sentinel, "unrecorded sensitive-path sentinel\n")
    identity = run(
        workspace.runner,
        ["stat", "-Lc", "%d:%i:%u:%a:%F", transaction],
        workspace.env,
    )
    assert_result(identity, 0)
    journal = workspace.pki / "state/csr/recovery-journal"
    write_private(journal, journal.read_text().replace("transaction_identity=none\n", f"transaction_identity={identity.stdout.strip()}\n"))
    metadata = sentinel.lstat()
    before = (
        stat.S_IMODE(metadata.st_mode), metadata.st_uid, metadata.st_gid,
        metadata.st_ino, metadata.st_size, metadata.st_mtime_ns, digest(sentinel),
    )

    recovered = run(
        workspace.runner,
        [RECOVER, "--namespace", workspace.namespace, "--transaction", "csr-0123456789abcdef0123456789abcdef", "--yes"],
        workspace.env,
    )

    metadata = sentinel.lstat()
    after = (
        stat.S_IMODE(metadata.st_mode), metadata.st_uid, metadata.st_gid,
        metadata.st_ino, metadata.st_size, metadata.st_mtime_ns, digest(sentinel),
    )
    assert recovered.status == 1
    assert "Journaled CSR signing key copy has no recorded identity" in recovered.stderr
    assert after == before
    assert (workspace.pki / "state/csr/recovery-journal").is_file()


def test_after_journal_recovery_rejects_foreign_transaction_tree(csr_workspace: CsrWorkspace) -> None:
    workspace = csr_workspace
    result = workspace.issue(env=environment(workspace.env, PLATFORM_PKI_CSR_CRASH_AT="after-journal"))
    assert result.status == 128 + signal.SIGKILL
    transaction = workspace.pki / "state/csr/transactions/csr-0123456789abcdef0123456789abcdef"
    transaction.mkdir(mode=0o700)
    sentinel = transaction / "sentinel"
    write_private(sentinel, "foreign after-journal transaction\n")
    before = (transaction.stat().st_ino, tree_snapshot(transaction))

    recovered = run(
        workspace.runner,
        [RECOVER, "--namespace", workspace.namespace, "--transaction", "csr-0123456789abcdef0123456789abcdef", "--yes"],
        workspace.env,
    )

    assert recovered.status == 1
    assert "Unowned CSR recovery transaction directory appeared" in recovered.stderr
    assert (transaction.stat().st_ino, tree_snapshot(transaction)) == before
    assert not (transaction / "terminal").exists()
    assert (workspace.pki / "state/csr/recovery-journal").is_file()


def test_csr_input_cleanup_preserves_foreign_replacement(
    csr_workspace: CsrWorkspace, process_starter
) -> None:
    workspace = csr_workspace
    temporary = workspace.artifacts / "csr-input-tmp"
    temporary.mkdir(mode=0o700)
    foreign = workspace.artifacts / "foreign-csr-input"
    foreign.mkdir(mode=0o700)
    sentinel = foreign / "sentinel"
    write_private(sentinel, "foreign CSR input directory\n")
    sentinel_metadata = sentinel.lstat()
    before = (
        foreign.stat().st_ino,
        stat.S_IMODE(sentinel_metadata.st_mode),
        sentinel_metadata.st_uid,
        sentinel_metadata.st_gid,
        sentinel_metadata.st_ino,
        sentinel_metadata.st_size,
        sentinel_metadata.st_mtime_ns,
        digest(sentinel),
    )
    displaced = workspace.artifacts / "displaced-csr-input"
    marker = workspace.artifacts / "csr-input-race.marker"
    release = workspace.artifacts / "csr-input-race.release"
    arguments: list[object] = [
        ISSUE,
        "external",
        "--namespace",
        workspace.namespace,
        "--intermediate-pass-file",
        workspace.intermediate_pass,
        "--csr-file",
        workspace.artifacts / "tls.csr",
        "--request-file",
        workspace.artifacts / "request",
        "--request-signature",
        workspace.artifacts / "request.sig",
        "--approval-file",
        workspace.artifacts / "approval",
        "--approval-signature",
        workspace.artifacts / "approval.sig",
        "--response-key",
        workspace.response_key,
    ]
    process = process_starter(
        arguments,
        env=environment(
            workspace.env,
            TMPDIR=os.fspath(temporary),
            PLATFORM_PKI_CSR_PYTHON_WRITER_PAUSE_AT="tree-cleanup-before-mutation",
            PLATFORM_PKI_CSR_PYTHON_WRITER_PAUSE_MARKER=os.fspath(marker),
            PLATFORM_PKI_CSR_PYTHON_WRITER_PAUSE_RELEASE=os.fspath(release),
        ),
        timeout=120,
    )
    wait_for_path(marker, process)
    retained = tuple(temporary.glob("platform-pki-csr-sign.*"))
    assert len(retained) == 1
    original_tree = tree_snapshot(retained[0])
    retained[0].rename(displaced)
    foreign.rename(retained[0])
    release.touch()
    result = process.wait()

    retained = tuple(temporary.glob("platform-pki-csr-sign.*"))
    assert len(retained) == 1
    sentinel_metadata = retained[0].joinpath("sentinel").lstat()
    after = (
        retained[0].stat().st_ino,
        stat.S_IMODE(sentinel_metadata.st_mode),
        sentinel_metadata.st_uid,
        sentinel_metadata.st_gid,
        sentinel_metadata.st_ino,
        sentinel_metadata.st_size,
        sentinel_metadata.st_mtime_ns,
        digest(retained[0] / "sentinel"),
    )
    assert result.status == 1
    assert marker.is_file()
    assert displaced.is_dir()
    assert tree_snapshot(displaced) == original_tree
    assert after == before
    assert (workspace.pki / "state/csr/responses/external/0123456789abcdef0123456789abcdef").is_dir()
    assert not (workspace.pki / "state/csr/recovery-journal").exists()


@pytest.mark.parametrize(
    ("checkpoint", "kind"),
    (("candidate-published", "candidate"), ("response-published", "response")),
)
def test_recovery_rejects_same_content_replacement_after_publication_checkpoint(
    csr_workspace: CsrWorkspace, checkpoint: str, kind: str
) -> None:
    workspace = csr_workspace
    result = workspace.issue(env=environment(workspace.env, PLATFORM_PKI_CSR_CRASH_AT=checkpoint))
    assert result.status == 128 + signal.SIGKILL
    destination = workspace.pki / f"state/csr/{kind}s/external/0123456789abcdef0123456789abcdef"
    replacement = workspace.artifacts / f"replacement-{kind}"
    displaced = workspace.artifacts / f"displaced-{kind}"
    shutil.copytree(destination, replacement, copy_function=shutil.copy2)
    destination.rename(displaced)
    replacement.rename(destination)
    before = (destination.stat().st_ino, tree_snapshot(destination))

    recovered = run(
        workspace.runner,
        [RECOVER, "--namespace", workspace.namespace, "--transaction", "csr-0123456789abcdef0123456789abcdef", "--response-key", workspace.response_key, "--yes"],
        workspace.env,
    )

    assert recovered.status == 1
    assert f"Published CSR {kind} artifact identity changed" in recovered.stderr
    assert (destination.stat().st_ino, tree_snapshot(destination)) == before
    assert (workspace.pki / "state/csr/recovery-journal").is_file()


def test_recovery_binds_exact_stage_identity_after_precheckpoint_rename(
    csr_workspace: CsrWorkspace,
) -> None:
    workspace = csr_workspace
    destination = workspace.pki / "state/csr/candidates/external/0123456789abcdef0123456789abcdef"

    result = workspace.issue(
        env=environment(
            workspace.env,
            PLATFORM_PKI_CSR_PYTHON_WRITER_CRASH_AT="candidate-publish-after-mutation",
        )
    )

    assert result.status == 128 + signal.SIGKILL
    assert destination.is_dir()
    identity = destination.stat().st_ino
    recovered = run(
        workspace.runner,
        [RECOVER, "--namespace", workspace.namespace, "--transaction", "csr-0123456789abcdef0123456789abcdef", "--response-key", workspace.response_key, "--yes"],
        workspace.env,
    )
    assert_result(recovered, 0)
    assert destination.stat().st_ino == identity


def test_recovery_does_not_mutate_unowned_allowed_name_artifact_stage(csr_workspace: CsrWorkspace) -> None:
    workspace = csr_workspace
    result = workspace.issue(env=environment(workspace.env, PLATFORM_PKI_CSR_CRASH_AT="response-signed"))
    assert result.status == 128 + signal.SIGKILL
    stage = workspace.pki / "state/csr/transactions/csr-0123456789abcdef0123456789abcdef/candidate.publish"
    stage.mkdir(mode=0o700)
    sentinel = stage / "tls.crt"
    write_private(sentinel, "unowned allowed-name stage sentinel\n")
    before = (stage.stat().st_ino, tree_snapshot(stage))

    recovered = run(
        workspace.runner,
        [RECOVER, "--namespace", workspace.namespace, "--transaction", "csr-0123456789abcdef0123456789abcdef", "--response-key", workspace.response_key, "--yes"],
        workspace.env,
    )

    assert recovered.status == 1
    assert "Unowned staged CSR candidate artifact already exists" in recovered.stderr
    assert (stage.stat().st_ino, tree_snapshot(stage)) == before
    assert (workspace.pki / "state/csr/recovery-journal").is_file()


@pytest.mark.parametrize("case", ("symlink", "hardlink", "mode", "replacement"))
def test_recovery_rejects_unsafe_or_replaced_replay_record(csr_workspace: CsrWorkspace, case: str) -> None:
    workspace = csr_workspace
    result = workspace.issue(env=environment(workspace.env, PLATFORM_PKI_CSR_CRASH_AT="replay-reserved"))
    assert result.status == 128 + signal.SIGKILL
    journal_text = (workspace.pki / "state/csr/recovery-journal").read_text()
    assert re.search(r"^replay_request_identity=(?!none$).+$", journal_text, re.MULTILINE)
    assert re.search(r"^replay_nonce_identity=(?!none$).+$", journal_text, re.MULTILINE)
    replay = workspace.pki / "state/csr/replay/requests/0123456789abcdef0123456789abcdef"
    original_content = replay.read_text()
    companion = replay.with_name(f"{replay.name}.{case}")
    if case == "symlink":
        replay.rename(companion)
        replay.symlink_to(companion.name)
    elif case == "hardlink":
        os.link(replay, companion)
    elif case == "mode":
        replay.chmod(0o640)
    else:
        replay.unlink()
        write_private(replay, original_content)
    before = replay.lstat()
    before_state = (before.st_mode, before.st_ino, before.st_nlink, before.st_size, before.st_mtime_ns, original_content)

    recovered = run(
        workspace.runner,
        [RECOVER, "--namespace", workspace.namespace, "--transaction", "csr-0123456789abcdef0123456789abcdef", "--yes"],
        workspace.env,
    )

    after = replay.lstat()
    after_state = (after.st_mode, after.st_ino, after.st_nlink, after.st_size, after.st_mtime_ns, replay.read_text())
    assert recovered.status == 1
    assert ("CSR request replay record is unsafe" if case != "replacement" else "CSR request replay record identity changed") in recovered.stderr
    assert after_state == before_state
    assert (workspace.pki / "state/csr/recovery-journal").is_file()


def test_recovery_does_not_recreate_missing_journaled_replay_record(csr_workspace: CsrWorkspace) -> None:
    workspace = csr_workspace
    result = workspace.issue(env=environment(workspace.env, PLATFORM_PKI_CSR_CRASH_AT="replay-reserved"))
    assert result.status == 128 + signal.SIGKILL
    replay = workspace.pki / "state/csr/replay/requests/0123456789abcdef0123456789abcdef"
    replay.unlink()

    recovered = run(
        workspace.runner,
        [RECOVER, "--namespace", workspace.namespace, "--transaction", "csr-0123456789abcdef0123456789abcdef", "--yes"],
        workspace.env,
    )

    assert recovered.status == 1
    assert "CSR request replay record disappeared after its identity was journaled" in recovered.stderr
    assert not replay.exists()
    assert (workspace.pki / "state/csr/recovery-journal").is_file()


def test_recovery_rejects_changed_published_candidate_record(csr_workspace: CsrWorkspace) -> None:
    workspace = csr_workspace
    result = workspace.issue(env=environment(workspace.env, PLATFORM_PKI_CSR_CRASH_AT="candidate-published"))
    assert result.status == 128 + signal.SIGKILL
    candidate = workspace.pki / "state/csr/candidates/external/0123456789abcdef0123456789abcdef/candidate"
    candidate.write_text(candidate.read_text().replace("state=pending", "state=changed"))
    candidate.chmod(0o600)

    recovered = run(
        workspace.runner,
        [
            RECOVER,
            "--namespace",
            workspace.namespace,
            "--transaction",
            "csr-0123456789abcdef0123456789abcdef",
            "--response-key",
            workspace.response_key,
            "--yes",
        ],
        workspace.env,
    )

    assert recovered.status == 1
    assert "Published CSR candidate record changed" in recovered.stderr
    assert "state=changed\n" in candidate.read_text()
    assert (workspace.pki / "state/csr/recovery-journal").is_file()


@pytest.mark.parametrize(
    ("checkpoint", "kind", "entry_kind", "entry_name"),
    (
        pytest.param("response-signed", "candidate", "file", "tls.key", id="candidate-stage-key"),
        pytest.param("response-signed", "response", "directory", "extra", id="response-stage-directory"),
        pytest.param("response-signed", "candidate", "symlink", "extra", id="candidate-stage-symlink"),
        pytest.param("candidate-published", "candidate-destination", "file", "extra", id="candidate-destination-extra"),
        pytest.param("response-published", "response-destination", "file", "tls.key", id="response-destination-key"),
    ),
)
def test_recovery_rejects_unexpected_publication_tree_entries(
    csr_workspace: CsrWorkspace, checkpoint: str, kind: str, entry_kind: str, entry_name: str
) -> None:
    workspace = csr_workspace
    result = workspace.issue(env=environment(workspace.env, PLATFORM_PKI_CSR_CRASH_AT=checkpoint))
    assert result.status == 128 + signal.SIGKILL
    transaction = workspace.pki / "state/csr/transactions/csr-0123456789abcdef0123456789abcdef"
    roots = {
        "candidate": transaction / "candidate.publish",
        "response": transaction / "response.publish",
        "candidate-destination": workspace.pki / "state/csr/candidates/external/0123456789abcdef0123456789abcdef",
        "response-destination": workspace.pki / "state/csr/responses/external/0123456789abcdef0123456789abcdef",
    }
    root = roots[kind]
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    root.chmod(0o700)
    entry = root / entry_name
    if entry_kind == "file":
        write_private(entry, "unexpected publication entry\n")
    elif entry_kind == "directory":
        entry.mkdir(mode=0o700)
    else:
        entry.symlink_to(workspace.artifacts / "request")

    recovered = run(
        workspace.runner,
        [
            RECOVER,
            "--namespace",
            workspace.namespace,
            "--transaction",
            "csr-0123456789abcdef0123456789abcdef",
            "--response-key",
            workspace.response_key,
            "--yes",
        ],
        workspace.env,
    )

    assert recovered.status == 1
    assert "artifact directory has unexpected or unsafe entries" in recovered.stderr
    if checkpoint == "response-signed":
        assert not (workspace.pki / "state/csr/candidates/external/0123456789abcdef0123456789abcdef").exists()
        assert not (workspace.pki / "state/csr/responses/external/0123456789abcdef0123456789abcdef").exists()
    assert entry.exists() or entry.is_symlink()
    assert (workspace.pki / "state/csr/recovery-journal").is_file()


@pytest.mark.parametrize(
    "relative",
    (
        "signing/tls.crt",
        "signing/ca-chain.crt",
        "signing/fullchain.crt",
        "signing/response",
        "responses.allowed_signers",
    ),
)
def test_post_commit_recovery_prevalidates_every_source_before_publication(csr_workspace: CsrWorkspace, relative: str) -> None:
    workspace = csr_workspace
    result = workspace.issue(env=environment(workspace.env, PLATFORM_PKI_CSR_CRASH_AT="ca-committed"))
    assert result.status == 128 + signal.SIGKILL
    transaction = workspace.pki / "state/csr/transactions/csr-0123456789abcdef0123456789abcdef"
    source = transaction / relative
    source.unlink()
    write_private(source, "replacement source\n")

    recovered = run(
        workspace.runner,
        [RECOVER, "--namespace", workspace.namespace, "--transaction", transaction.name, "--response-key", workspace.response_key, "--yes"],
        workspace.env,
    )

    assert recovered.status == 1
    assert not (workspace.pki / "state/csr/candidates/external/0123456789abcdef0123456789abcdef").exists()
    assert not (workspace.pki / "state/csr/responses/external/0123456789abcdef0123456789abcdef").exists()
    assert not (transaction / "candidate.publish").exists()
    assert not (transaction / "response.publish").exists()


def test_recovery_rejects_replaced_checkpointed_response_signature_without_resigning(csr_workspace: CsrWorkspace) -> None:
    workspace = csr_workspace
    result = workspace.issue(env=environment(workspace.env, PLATFORM_PKI_CSR_CRASH_AT="response-signed"))
    assert result.status == 128 + signal.SIGKILL
    transaction = workspace.pki / "state/csr/transactions/csr-0123456789abcdef0123456789abcdef"
    signature = transaction / "signing/response.sig"
    signature.unlink()
    write_private(signature, "replacement signature\n")
    replacement = (signature.stat().st_ino, digest(signature))

    recovered = run(
        workspace.runner,
        [RECOVER, "--namespace", workspace.namespace, "--transaction", transaction.name, "--response-key", workspace.response_key, "--yes"],
        workspace.env,
    )

    assert recovered.status == 1
    assert "Journaled CSR response signature identity changed" in recovered.stderr
    assert (signature.stat().st_ino, digest(signature)) == replacement
    assert not (transaction / "candidate.publish").exists()
    assert not (workspace.pki / "state/csr/candidates/external/0123456789abcdef0123456789abcdef").exists()


@pytest.mark.parametrize(
    ("digest_name", "attributes"),
    (
        pytest.param("sha256", (), id="sha256"),
        pytest.param("sha512", (), id="sha512"),
        pytest.param("sha384", ("unstructuredName = arbitrary",), id="arbitrary-attribute"),
        pytest.param("sha384", ("challengePassword = challenge-value",), id="challenge-password"),
        pytest.param(
            "sha384",
            ("unstructuredName = first", "challengePassword = second"),
            id="multiple-unsupported-attributes",
        ),
    ),
)
def test_csr_signature_algorithm_and_attributes_fail_before_replay(
    csr_workspace: CsrWorkspace, digest_name: str, attributes: tuple[str, ...]
) -> None:
    workspace = csr_workspace
    authority = workspace.pki / "authorities/intermediates/g1-i1"
    before = tree_snapshot(authority)
    write_csr(workspace, digest_name=digest_name, attributes=attributes)

    result = workspace.issue()

    assert result.status == 1
    assert tree_snapshot(authority) == before
    assert not (workspace.pki / "state/csr/replay/requests/0123456789abcdef0123456789abcdef").exists()
    assert not (workspace.pki / "state/csr/recovery-journal").exists()


def test_trusted_requester_cannot_claim_a_different_target(csr_workspace: CsrWorkspace) -> None:
    workspace = csr_workspace
    request = workspace.artifacts / "request"
    request_content = request.read_text().replace("target=host-01\n", "target=host-02\n")
    write_private(request, request_content)
    (workspace.artifacts / "request.sig").unlink()
    sign(workspace.runner, workspace.env, workspace.requester_key, "platform-pki-csr-request-v1", request)
    approval = workspace.artifacts / "approval"
    approval_lines = approval.read_text().splitlines()
    approval_lines = [
        "target=host-02" if line == "target=host-01" else
        f"request_sha256={digest(request)}" if line.startswith("request_sha256=") else line
        for line in approval_lines
    ]
    write_private(approval, "\n".join(approval_lines) + "\n")
    (workspace.artifacts / "approval.sig").unlink()
    sign(workspace.runner, workspace.env, workspace.approver_key, "platform-pki-csr-approval-v1", approval)
    authority = workspace.pki / "authorities/intermediates/g1-i1"
    before = tree_snapshot(authority)

    result = workspace.issue()

    assert result.status == 1
    assert "CSR requester principal must exactly match the target identity" in result.stderr
    assert tree_snapshot(authority) == before
    assert not (workspace.pki / "state/csr/recovery-journal").exists()
    assert not (workspace.pki / "state/csr/replay/requests/0123456789abcdef0123456789abcdef").exists()
    assert not (workspace.pki / "state/csr/replay/nonces" / ("ab" * 32)).exists()


def test_recovery_does_not_use_external_stat_for_journal_identity(
    csr_workspace: CsrWorkspace, executable_directory: Path
) -> None:
    workspace = csr_workspace
    result = workspace.issue(env=environment(workspace.env, PLATFORM_PKI_CSR_CRASH_AT="ca-committed"))
    assert result.status == 128 + signal.SIGKILL
    journal = workspace.pki / "state/csr/recovery-journal"
    authority = workspace.pki / "authorities/intermediates/g1-i1"
    before = tree_snapshot(authority)
    fake_bin = executable_directory / "journal-race"
    marker = workspace.artifacts / "journal-race.marker"
    write_executable(
        fake_bin / "stat",
        """#!/usr/bin/env bash
set -euo pipefail
for argument in "$@"; do
  if [[ $argument == /proc/self/fd/* && ! -e $RACE_MARKER ]] && [[ $(readlink -- "$argument") == "$RACE_JOURNAL" ]]; then
    cp -p -- "$RACE_JOURNAL" "$RACE_JOURNAL.replacement"
    mv -T -- "$RACE_JOURNAL.replacement" "$RACE_JOURNAL"
    : >"$RACE_MARKER"
  fi
done
exec "$REAL_STAT" "$@"
""",
    )

    recovered = run(
        workspace.runner,
        [RECOVER, "--namespace", workspace.namespace, "--transaction", "csr-0123456789abcdef0123456789abcdef", "--response-key", workspace.response_key, "--yes"],
        environment(
            workspace.env,
            PATH=f"{fake_bin}:{workspace.env['PATH']}",
            RACE_MARKER=os.fspath(marker),
            RACE_JOURNAL=os.fspath(journal),
            REAL_STAT=executable("stat"),
        ),
    )

    assert_result(recovered, 0)
    assert not marker.exists()
    assert not journal.exists()
    assert tree_snapshot(authority) == before


def test_response_signing_uses_identity_bound_key_descriptor(
    csr_workspace: CsrWorkspace, executable_directory: Path
) -> None:
    workspace = csr_workspace
    result = workspace.issue(env=environment(workspace.env, PLATFORM_PKI_CSR_CRASH_AT="ca-committed"))
    assert result.status == 128 + signal.SIGKILL
    replacement = workspace.artifacts / "replacement-response-key"
    ssh_key(workspace.runner, workspace.env, replacement)
    fake_bin = executable_directory / "response-key-race"
    marker = workspace.artifacts / "response-key-race.marker"
    log = workspace.artifacts / "response-key-race.argv"
    write_executable(
        fake_bin / "ssh-keygen",
        """#!/usr/bin/env bash
set -euo pipefail
printf '<%s>\n' "$@" >>"$RACE_LOG"
if [[ $* == *'-Y sign'* && ! -e $RACE_MARKER ]]; then
  mv -T -- "$RACE_REPLACEMENT" "$RACE_KEY"
  : >"$RACE_MARKER"
fi
exec "$REAL_SSH_KEYGEN" "$@"
""",
    )

    recovered = run(
        workspace.runner,
        [RECOVER, "--namespace", workspace.namespace, "--transaction", "csr-0123456789abcdef0123456789abcdef", "--response-key", workspace.response_key, "--yes"],
        environment(
            workspace.env,
            PATH=f"{fake_bin}:{workspace.env['PATH']}",
            RACE_KEY=os.fspath(workspace.response_key),
            RACE_REPLACEMENT=os.fspath(replacement),
            RACE_MARKER=os.fspath(marker),
            RACE_LOG=os.fspath(log),
            REAL_SSH_KEYGEN=executable("ssh-keygen"),
        ),
    )

    assert recovered.status == 1
    assert "Response signing key changed during signing" in recovered.stderr
    assert marker.is_file()
    assert os.fspath(workspace.response_key) not in log.read_text()
    assert not (workspace.pki / "state/csr/candidates/external/0123456789abcdef0123456789abcdef").exists()
    assert (workspace.pki / "state/csr/recovery-journal").is_file()


@pytest.mark.parametrize(
    ("record", "mutation", "message"),
    (
        pytest.param("request", "extra", "contains extra fields", id="request-extra-field"),
        pytest.param("request", "missing", "is missing required fields", id="request-missing-field"),
        pytest.param("request", "order", "field order is invalid", id="request-field-order"),
        pytest.param("request", "text", "contains invalid text", id="request-invalid-text"),
        pytest.param("approval", "extra", "contains extra fields", id="approval-extra-field"),
        pytest.param("approval", "missing", "is missing required fields", id="approval-missing-field"),
        pytest.param("approval", "order", "field order is invalid", id="approval-field-order"),
        pytest.param("approval", "text", "contains invalid text", id="approval-invalid-text"),
    ),
)
def test_protocol_records_require_exact_ordered_canonical_fields_before_replay(
    csr_workspace: CsrWorkspace, record: str, mutation: str, message: str
) -> None:
    workspace = csr_workspace
    authority = workspace.pki / "authorities/intermediates/g1-i1"
    before = tree_snapshot(authority)
    path = workspace.artifacts / record
    lines = path.read_text().splitlines()
    if mutation == "extra":
        lines.append("unexpected=value")
    elif mutation == "missing":
        lines.pop()
    elif mutation == "order":
        lines[1], lines[2] = lines[2], lines[1]
    else:
        lines[1] += "\tinvalid"
    path.unlink()
    write_private(path, "\n".join(lines) + "\n")

    result = workspace.issue()

    assert result.status == 1
    assert message in result.stderr
    assert tree_snapshot(authority) == before
    assert not (workspace.pki / "state/csr/recovery-journal").exists()
    assert not (workspace.pki / "state/csr/replay/requests/0123456789abcdef0123456789abcdef").exists()


@pytest.mark.parametrize(
    ("record", "field", "replacement", "message"),
    (
        pytest.param("request", "schema", "2", "schema is unsupported", id="request-schema"),
        pytest.param("request", "request_id", "invalid", "request ID or nonce is invalid", id="request-id"),
        pytest.param("request", "nonce", "invalid", "request ID or nonce is invalid", id="request-nonce"),
        pytest.param("request", "requester_principal", "INVALID", "service, target, or requester is invalid", id="request-principal"),
        pytest.param("request", "profile", "other", "profile or response signer is invalid", id="request-profile"),
        pytest.param("request", "response_principal", "other", "profile or response signer is invalid", id="request-response-principal"),
        pytest.param("approval", "schema", "2", "schema is unsupported", id="approval-schema"),
        pytest.param("approval", "request_id", "invalid", "does not bind request field: request_id", id="approval-invalid-request-id"),
        pytest.param("approval", "request_id", "1" * 32, "does not bind request field: request_id", id="approval-request-id"),
        pytest.param("approval", "nonce", "cd" * 32, "does not bind request field: nonce", id="approval-nonce"),
        pytest.param("approval", "operation", "renew", "does not bind request field: operation", id="approval-operation"),
        pytest.param("approval", "service", "other", "does not bind request field: service", id="approval-service"),
        pytest.param("approval", "target", "other", "does not bind request field: target", id="approval-target"),
        pytest.param("approval", "profile", "other", "does not bind request field: profile", id="approval-profile"),
        pytest.param("approval", "csr_sha256", "invalid", "does not bind request field: csr_sha256", id="approval-invalid-csr-digest"),
        pytest.param("approval", "request_sha256", "invalid", "digest binding failed", id="approval-invalid-request-digest"),
        pytest.param("approval", "approver_principal", "other", "principal does not match policy", id="approval-principal"),
    ),
)
def test_protocol_record_values_and_bindings_fail_before_replay(
    csr_workspace: CsrWorkspace, record: str, field: str, replacement: str, message: str
) -> None:
    workspace = csr_workspace
    authority = workspace.pki / "authorities/intermediates/g1-i1"
    before = tree_snapshot(authority)
    path = workspace.artifacts / record
    lines = path.read_text().splitlines()
    lines = [f"{field}={replacement}" if line.startswith(f"{field}=") else line for line in lines]
    path.unlink()
    write_private(path, "\n".join(lines) + "\n")

    result = workspace.issue()

    assert result.status == 1
    assert message in result.stderr
    assert tree_snapshot(authority) == before
    assert not (workspace.pki / "state/csr/recovery-journal").exists()
    assert not (workspace.pki / "state/csr/replay/requests/0123456789abcdef0123456789abcdef").exists()


@pytest.mark.parametrize("case", ("request-signature", "expired", "wrong-curve", "extra-san"))
def test_invalid_authenticated_request_fails_before_replay_or_ca_mutation(csr_workspace: CsrWorkspace, case: str) -> None:
    workspace = csr_workspace
    authority = workspace.pki / "authorities/intermediates/g1-i1"
    serial = (authority / "serial").read_text()
    if case == "request-signature":
        path = workspace.artifacts / "request"
        path.write_text(path.read_text().replace("target=host-01", "target=host-02"))
        path.chmod(0o600)
    elif case == "expired":
        now = int(time.time())
        write_exchange(
            workspace,
            "issue",
            "0123456789abcdef0123456789abcdef",
            "ab" * 32,
            "none",
            request_created=now - 7200,
            request_expires=now - 3600,
            approval_created=now - 7100,
            approval_expires=now - 3500,
        )
    else:
        curve = "prime256v1" if case == "wrong-curve" else "secp384r1"
        assert_result(
            run(workspace.runner, ["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", f"ec_paramgen_curve:{curve}", "-out", workspace.host_key], workspace.env),
            0,
        )
        sans = "DNS:unexpected.example.internal" if case == "extra-san" else "DNS:external.example.internal,DNS:external,IP:192.0.2.50"
        assert_result(
            run(
                workspace.runner,
                ["openssl", "req", "-new", "-sha384", "-key", workspace.host_key, "-subj", "/CN=external.example.internal", "-addext", f"subjectAltName={sans}", "-out", workspace.artifacts / "tls.csr"],
                workspace.env,
            ),
            0,
        )
        (workspace.artifacts / "tls.csr").chmod(0o600)
        write_exchange(workspace, "issue", "0123456789abcdef0123456789abcdef", "ab" * 32, "none")

    result = workspace.issue()

    assert result.status == 1
    assert (authority / "serial").read_text() == serial
    assert not (workspace.pki / "state/csr/replay/requests/0123456789abcdef0123456789abcdef").exists()
    assert not (workspace.pki / "state/csr/recovery-journal").exists()
