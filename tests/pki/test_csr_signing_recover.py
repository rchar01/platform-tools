from __future__ import annotations

import os
import re
import signal
import sys
import time
from collections.abc import Callable, Mapping
from pathlib import Path

import pytest

from src.platform_pki.csr_recover import CSR_SIGNING_RECOVERY_CHECKPOINTS

from ..harness import ManagedProcess, ProcessResult
from .migration_harness import (
    copy_private_case,
    managed_openssl_dir_normalizer,
    snapshot_state,
)
from .support import (
    assert_result,
    digest,
    environment,
    executable,
    executable_directory,
    write_executable,
    write_private,
)
from .test_csr_signing import CsrWorkspace, csr_workspace, write_exchange


pytestmark = pytest.mark.pki

REPOSITORY = Path(__file__).resolve().parents[2]
DRIVER = REPOSITORY / "tests/pki/csr_signing_recover_driver.py"
ORACLE_ROOT = REPOSITORY / "tests/pki/oracles/platform-pki-csr-recover"
BASH_RECOVER = ORACLE_ROOT / "platform-pki-csr-recover"
ORACLE_LIB = ORACLE_ROOT / "lib"
ISSUE_ORACLE_ROOT = REPOSITORY / "tests/pki/oracles/platform-pki-service-issue"
ISSUE_ORACLE = ISSUE_ORACLE_ROOT / "platform-pki-service-issue"
ISSUE_ORACLE_LIB = ISSUE_ORACLE_ROOT / "lib"
REQUEST_ID = "0123456789abcdef0123456789abcdef"
TRANSACTION = f"csr-{REQUEST_ID}"
WRITER_CHECKPOINTS = (
    "after-journal",
    "replay-reserved",
    "transaction-staged",
    "signing-ready",
    "signing-complete",
    "sensitive-key-removed",
    "after-ca-index-publish",
    "after-ca-index_attr-publish",
    "after-ca-serial-publish",
    "after-ca-index_old-publish",
    "after-ca-index_attr_old-publish",
    "after-ca-serial_old-publish",
    "after-ca-newcert-publish",
    "ca-committed",
    "response-signed",
    "candidate-published",
    "response-published",
    "before-journal-cleanup",
)
_ABSENT_PRE_ROLLBACK_KEYS = ("newcert", "serial_old", "index_attr_old", "index_old")
RESTART_CHECKPOINTS = tuple(
    point
    for point in CSR_SIGNING_RECOVERY_CHECKPOINTS
    if not (
        point.endswith(
            ("-before-evidence", "-after-evidence", "-after-journal-rewrite")
        )
        and any(
            point.startswith(f"rollback-{key}-")
            for key in _ABSENT_PRE_ROLLBACK_KEYS
        )
    )
)


def _workspace(
    root: Path,
    env: Mapping[str, str],
    runner: Callable[..., ProcessResult],
) -> CsrWorkspace:
    return CsrWorkspace(
        root / "namespace",
        root / "namespace/pki",
        root / "platform-private",
        root / "artifacts",
        root / "intermediate.pass",
        root / "keys/requester",
        root / "keys/approver",
        root / "keys/response",
        root / "artifacts/tls.key",
        env,
        runner,
    )


def _crash_writer(workspace: CsrWorkspace, checkpoint: str) -> None:
    result = workspace.sign(
        tool=ISSUE_ORACLE,
        env=environment(
            workspace.env,
            PLATFORM_PKI_CSR_CRASH_AT=checkpoint,
            PLATFORM_TOOLS_LIB_DIR=os.fspath(ISSUE_ORACLE_LIB),
        ),
    )
    assert result.status == 128 + signal.SIGKILL, (checkpoint, result)


def _journal_values(workspace: CsrWorkspace) -> dict[str, str]:
    return dict(
        line.split("=", 1)
        for line in (workspace.pki / "state/csr/recovery-journal")
        .read_text(encoding="ascii")
        .splitlines()
    )


def _python_recover(
    workspace: CsrWorkspace,
    *,
    env: Mapping[str, str] | None = None,
    response_key: Path | None = None,
) -> ProcessResult:
    command: list[object] = [
        sys.executable,
        DRIVER,
        "--pki-dir",
        workspace.pki,
        "--transaction",
        TRANSACTION,
    ]
    if response_key is not None:
        command.extend(("--response-key", response_key))
    return workspace.runner(
        command,
        env=workspace.env if env is None else env,
        timeout=120,
    )


def _is_committed(workspace: CsrWorkspace) -> bool:
    return _journal_values(workspace)["committed"] == "true"


@pytest.mark.parametrize("checkpoint", WRITER_CHECKPOINTS)
def test_python_recovers_every_final_bash_signing_checkpoint(
    csr_workspace: CsrWorkspace,
    checkpoint: str,
) -> None:
    authority = csr_workspace.pki / "authorities/intermediates/g1-i1"
    before = snapshot_state(authority)
    _crash_writer(csr_workspace, checkpoint)
    committed = _is_committed(csr_workspace)

    result = _python_recover(
        csr_workspace,
        response_key=csr_workspace.response_key if committed else None,
    )

    assert_result(result, 0, stderr="")
    assert not (csr_workspace.pki / "state/csr/recovery-journal").exists()
    assert (
        csr_workspace.pki / f"state/csr/replay/requests/{REQUEST_ID}"
    ).is_file()
    if committed:
        assert (
            csr_workspace.pki / f"state/csr/candidates/external/{REQUEST_ID}"
        ).is_dir()
        assert (
            csr_workspace.pki / f"state/csr/responses/external/{REQUEST_ID}"
        ).is_dir()
        assert snapshot_state(authority) != before
    else:
        assert snapshot_state(authority) == before
        assert not (
            csr_workspace.pki / f"state/csr/candidates/external/{REQUEST_ID}"
        ).exists()
    repeated = csr_workspace.issue()
    assert repeated.status == 1
    assert "CSR request ID has already been consumed" in repeated.stderr


def _writer_checkpoint_for_recovery_point(point: str) -> str:
    if point.startswith("replay-") or point in {
        "signing-journal-loaded",
        "terminal-before-mutation",
        "terminal-after-mutation",
        "terminal-before-evidence",
        "terminal-after-evidence",
        "terminal-after-journal-rewrite",
    }:
        return "after-journal"
    if point.startswith("rollback-"):
        return "after-ca-newcert-publish"
    if point.startswith("sensitive-key-"):
        return "signing-complete"
    return "ca-committed"


@pytest.mark.parametrize(
    "point",
    RESTART_CHECKPOINTS,
    ids=RESTART_CHECKPOINTS,
)
def test_python_signing_recovery_restarts_after_every_recovery_checkpoint(
    csr_workspace: CsrWorkspace,
    point: str,
) -> None:
    writer_checkpoint = _writer_checkpoint_for_recovery_point(point)
    _crash_writer(csr_workspace, writer_checkpoint)
    committed = _is_committed(csr_workspace)
    crashed = _python_recover(
        csr_workspace,
        response_key=csr_workspace.response_key if committed else None,
        env=environment(
            csr_workspace.env,
            PLATFORM_PKI_CSR_PYTHON_RECOVER_CRASH_AT=point,
        ),
    )
    assert crashed.status == 128 + signal.SIGKILL, (point, crashed)
    journal = csr_workspace.pki / "state/csr/recovery-journal"
    assert journal.is_file()

    recovered = _python_recover(
        csr_workspace,
        response_key=csr_workspace.response_key if committed else None,
    )

    assert_result(recovered, 0, stderr="")
    assert not journal.exists()


def _replace(path: Path, data: bytes | None = None) -> None:
    replacement = path.with_name(f".{path.name}.replacement")
    replacement.write_bytes(path.read_bytes() if data is None else data)
    replacement.chmod(0o600)
    os.replace(replacement, path)


@pytest.mark.parametrize(
    "kind",
    (
        "journal",
        "replay",
        "db",
        "trust",
        "certificate",
        "stage",
        "destination",
        "simultaneous-journal",
    ),
)
def test_python_signing_recovery_rejects_hostile_replacement_or_incompatible_state(
    csr_workspace: CsrWorkspace,
    kind: str,
) -> None:
    checkpoint = "ca-committed" if kind in {
        "journal",
        "db",
        "trust",
        "certificate",
        "stage",
        "destination",
        "simultaneous-journal",
    } else "replay-reserved"
    _crash_writer(csr_workspace, checkpoint)
    values = _journal_values(csr_workspace)
    if kind == "journal":
        _replace(csr_workspace.pki / "state/csr/recovery-journal", b"schema=1\n")
    elif kind == "replay":
        _replace(Path(values["replay_request_path"]))
    elif kind == "db":
        _replace(Path(values["db_serial_path"]))
    elif kind == "trust":
        _replace(Path(values["response_trust_path"]))
    elif kind == "certificate":
        _replace(Path(values["certificate_path"]))
    elif kind == "stage":
        stage = Path(values["candidate_stage"])
        stage.mkdir(mode=0o700)
        write_private(stage / "unexpected", "hostile stage\n")
    elif kind == "destination":
        destination = Path(values["candidate_destination"])
        destination.mkdir(mode=0o700)
        write_private(destination / "unexpected", "hostile destination\n")
    else:
        write_private(
            csr_workspace.pki / "state/csr/finalization-recovery-journal",
            "operation=csr-finalize\n",
        )
    before = snapshot_state(csr_workspace.pki)

    result = _python_recover(
        csr_workspace,
        response_key=csr_workspace.response_key if checkpoint == "ca-committed" else None,
    )

    assert result.status == 1, (kind, result)
    assert result.stdout == ""
    assert snapshot_state(csr_workspace.pki) == before
    assert (csr_workspace.pki / "state/csr/recovery-journal").is_file()


def _wait(
    path: Path,
    timeout: float = 30.0,
    process: ManagedProcess | None = None,
) -> None:
    deadline = time.monotonic() + timeout
    while not path.exists():
        if process is not None:
            observation = process.observe()
            if observation.status is not None:
                pytest.fail(
                    f"process exited before {path}: {observation}",
                    pytrace=False,
                )
        if time.monotonic() >= deadline:
            pytest.fail(f"timed out waiting for {path}", pytrace=False)
        time.sleep(0.01)


@pytest.mark.parametrize(
    ("checkpoint", "kind"),
    (
        pytest.param("after-ca-newcert-publish", "sensitive-key", id="uncommitted-key"),
        pytest.param("after-ca-newcert-publish", "terminal", id="uncommitted-terminal"),
        pytest.param("ca-committed", "sensitive-key", id="committed-key"),
        pytest.param("ca-committed", "terminal", id="committed-terminal"),
    ),
)
def test_branch_preflight_rejects_hostile_key_or_terminal_before_mutation(
    csr_workspace: CsrWorkspace,
    checkpoint: str,
    kind: str,
) -> None:
    _crash_writer(csr_workspace, checkpoint)
    values = _journal_values(csr_workspace)
    path = (
        Path(values["sensitive_key_path"])
        if kind == "sensitive-key"
        else Path(values["transaction_dir"]) / "terminal"
    )
    write_private(path, "hostile preflight state\n")
    before = snapshot_state(csr_workspace.pki)

    result = _python_recover(
        csr_workspace,
        response_key=(
            csr_workspace.response_key if checkpoint == "ca-committed" else None
        ),
    )

    assert result.status == 1, result
    assert result.stdout == ""
    assert snapshot_state(csr_workspace.pki) == before


@pytest.mark.parametrize("key", ("newcert", "serial"))
def test_rollback_rechecks_current_object_immediately_before_mutation(
    csr_workspace: CsrWorkspace,
    process_starter,
    key: str,
) -> None:
    _crash_writer(csr_workspace, "after-ca-newcert-publish")
    values = _journal_values(csr_workspace)
    marker = csr_workspace.artifacts / f"rollback-{key}-pause"
    release = csr_workspace.artifacts / f"rollback-{key}-release"
    process = process_starter(
        [
            sys.executable,
            DRIVER,
            "--pki-dir",
            csr_workspace.pki,
            "--transaction",
            TRANSACTION,
        ],
        env=environment(
            csr_workspace.env,
            PLATFORM_PKI_CSR_PYTHON_RECOVER_PAUSE_AT=(
                f"rollback-{key}-before-mutation"
            ),
            PLATFORM_PKI_CSR_PYTHON_RECOVER_PAUSE_MARKER=os.fspath(marker),
            PLATFORM_PKI_CSR_PYTHON_RECOVER_PAUSE_RELEASE=os.fspath(release),
        ),
        timeout=120,
    )
    with process:
        _wait(marker, process=process)
        _replace(Path(values[f"db_{key}_path"]), b"hostile rollback target\n")
        before_release = snapshot_state(csr_workspace.pki)
        release.touch(mode=0o600)
        result = process.wait()

    assert result.status == 1, result
    assert result.stdout == ""
    assert snapshot_state(csr_workspace.pki) == before_release


def test_rollback_rechecks_restored_object_before_recording_evidence(
    csr_workspace: CsrWorkspace,
    process_starter,
) -> None:
    _crash_writer(csr_workspace, "after-ca-newcert-publish")
    crashed = _python_recover(
        csr_workspace,
        env=environment(
            csr_workspace.env,
            PLATFORM_PKI_CSR_PYTHON_RECOVER_CRASH_AT=(
                "rollback-serial-after-mutation"
            ),
        ),
    )
    assert crashed.status == 128 + signal.SIGKILL, crashed
    values = _journal_values(csr_workspace)
    marker = csr_workspace.artifacts / "rollback-serial-evidence-pause"
    release = csr_workspace.artifacts / "rollback-serial-evidence-release"
    process = process_starter(
        [
            sys.executable,
            DRIVER,
            "--pki-dir",
            csr_workspace.pki,
            "--transaction",
            TRANSACTION,
        ],
        env=environment(
            csr_workspace.env,
            PLATFORM_PKI_CSR_PYTHON_RECOVER_PAUSE_AT=(
                "rollback-serial-before-evidence"
            ),
            PLATFORM_PKI_CSR_PYTHON_RECOVER_PAUSE_MARKER=os.fspath(marker),
            PLATFORM_PKI_CSR_PYTHON_RECOVER_PAUSE_RELEASE=os.fspath(release),
        ),
        timeout=120,
    )
    with process:
        _wait(marker, process=process)
        _replace(Path(values["db_serial_path"]), b"hostile restored target\n")
        before_release = snapshot_state(csr_workspace.pki)
        release.touch(mode=0o600)
        result = process.wait()

    assert result.status == 1, result
    assert result.stdout == ""
    assert snapshot_state(csr_workspace.pki) == before_release


@pytest.mark.parametrize(
    ("point", "replacement"),
    (
        pytest.param("candidate-publish-before-mutation", "db", id="candidate-db"),
        pytest.param(
            "candidate-publish-before-mutation", "source", id="candidate-source"
        ),
        pytest.param("response-publish-before-mutation", "db", id="response-db"),
        pytest.param(
            "response-publish-before-mutation", "source", id="response-source"
        ),
    ),
)
def test_publication_rechecks_database_and_sources_in_authorization_window(
    csr_workspace: CsrWorkspace,
    process_starter,
    point: str,
    replacement: str,
) -> None:
    _crash_writer(csr_workspace, "ca-committed")
    values = _journal_values(csr_workspace)
    marker = csr_workspace.artifacts / f"{point}-{replacement}-pause"
    release = csr_workspace.artifacts / f"{point}-{replacement}-release"
    process = process_starter(
        [
            sys.executable,
            DRIVER,
            "--pki-dir",
            csr_workspace.pki,
            "--transaction",
            TRANSACTION,
            "--response-key",
            csr_workspace.response_key,
        ],
        env=environment(
            csr_workspace.env,
            PLATFORM_PKI_CSR_PYTHON_RECOVER_PAUSE_AT=point,
            PLATFORM_PKI_CSR_PYTHON_RECOVER_PAUSE_MARKER=os.fspath(marker),
            PLATFORM_PKI_CSR_PYTHON_RECOVER_PAUSE_RELEASE=os.fspath(release),
        ),
        timeout=120,
    )
    with process:
        _wait(marker)
        path = Path(
            values["db_serial_path"]
            if replacement == "db"
            else values["certificate_path"]
        )
        _replace(path)
        before_release = snapshot_state(csr_workspace.pki)
        release.touch(mode=0o600)
        result = process.wait()

    assert result.status == 1, result
    assert result.stdout == ""
    assert snapshot_state(csr_workspace.pki) == before_release


def test_response_signing_subprocess_uses_only_inherited_descriptors_and_suppresses_output(
    csr_workspace: CsrWorkspace,
    executable_directory: Path,
) -> None:
    _crash_writer(csr_workspace, "ca-committed")
    fake_bin = executable_directory / "ssh-keygen-audit"
    argv_log = csr_workspace.artifacts / "ssh-keygen.argv"
    descriptor_log = csr_workspace.artifacts / "ssh-keygen.descriptors"
    environment_log = csr_workspace.artifacts / "ssh-keygen.environment"
    write_executable(
        fake_bin / "ssh-keygen",
        """#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' '---' >>"$ARGV_LOG"
printf '<%s>\n' "$@" >>"$ARGV_LOG"
tr '\\0' '\\n' </proc/self/environ >"$ENVIRONMENT_LOG"
for argument in "$@"; do
  case $argument in
    /proc/self/fd/*)
      test -r "$argument"
      printf '%s=%s\n' "$argument" "$(readlink "$argument")" >>"$DESCRIPTOR_LOG"
      ;;
  esac
done
printf '%s\n' 'raw ssh-keygen diagnostic' >&2
exec "$REAL_SSH_KEYGEN" "$@"
""",
    )

    result = _python_recover(
        csr_workspace,
        response_key=csr_workspace.response_key,
        env=environment(
            csr_workspace.env,
            PATH=f"{fake_bin}:{csr_workspace.env['PATH']}",
            ARGV_LOG=os.fspath(argv_log),
            DESCRIPTOR_LOG=os.fspath(descriptor_log),
            ENVIRONMENT_LOG=os.fspath(environment_log),
            REAL_SSH_KEYGEN=executable("ssh-keygen"),
        ),
    )

    assert_result(result, 0, stderr="")
    argv = argv_log.read_text(encoding="utf-8")
    descriptors = descriptor_log.read_text(encoding="utf-8")
    child_environment = environment_log.read_text(encoding="utf-8")
    key_path = os.fspath(csr_workspace.response_key)
    assert key_path not in argv
    assert key_path not in child_environment
    assert "/proc/self/fd/" in argv
    assert key_path in descriptors
    assert "PRIVATE KEY" not in result.stdout
    assert "PRIVATE KEY" not in result.stderr
    assert "raw ssh-keygen diagnostic" not in result.stderr


def test_response_signing_key_replacement_is_detected_and_key_path_is_not_on_argv(
    csr_workspace: CsrWorkspace,
    process_starter,
) -> None:
    _crash_writer(csr_workspace, "ca-committed")
    marker = csr_workspace.artifacts / "key-pause"
    release = csr_workspace.artifacts / "key-release"
    process = process_starter(
        [
            sys.executable,
            DRIVER,
            "--pki-dir",
            csr_workspace.pki,
            "--transaction",
            TRANSACTION,
            "--response-key",
            csr_workspace.response_key,
        ],
        env=environment(
            csr_workspace.env,
            PLATFORM_PKI_CSR_PYTHON_RECOVER_PAUSE_AT="response-signature-before-mutation",
            PLATFORM_PKI_CSR_PYTHON_RECOVER_PAUSE_MARKER=os.fspath(marker),
            PLATFORM_PKI_CSR_PYTHON_RECOVER_PAUSE_RELEASE=os.fspath(release),
        ),
        timeout=120,
    )
    with process:
        _wait(marker)
        replacement = csr_workspace.response_key.with_name("response.replacement")
        replacement.write_bytes(csr_workspace.response_key.read_bytes())
        replacement.chmod(0o600)
        os.replace(replacement, csr_workspace.response_key)
        release.touch(mode=0o600)
        result = process.wait()
    assert result.status == 1, result
    assert "Response signing key changed during signing" in result.stderr
    assert not (
        csr_workspace.pki / f"state/csr/candidates/external/{REQUEST_ID}"
    ).exists()


def test_python_signing_recovery_requires_matching_transaction(
    csr_workspace: CsrWorkspace,
) -> None:
    _crash_writer(csr_workspace, "after-journal")
    result = csr_workspace.runner(
        [
            sys.executable,
            DRIVER,
            "--pki-dir",
            csr_workspace.pki,
            "--transaction",
            f"csr-{'f' * 32}",
        ],
        env=csr_workspace.env,
        timeout=120,
    )
    assert result.status == 1
    assert "does not match" in result.stderr
    assert (csr_workspace.pki / "state/csr/recovery-journal").is_file()


@pytest.mark.parametrize("checkpoint", WRITER_CHECKPOINTS)
def test_final_bash_and_python_signing_recovery_have_equivalent_terminal_state(
    tmp_path: Path,
    csr_workspace: CsrWorkspace,
    process_runner: Callable[..., ProcessResult],
    isolated_environment: Mapping[str, str],
    checkpoint: str,
) -> None:
    seed = csr_workspace.namespace.parent
    case = tmp_path / "differential"
    bash_root = case / "bash"
    python_root = case / "python"
    case.mkdir(mode=0o700)
    for root in (bash_root, python_root):
        copy_private_case(seed, root, Path("namespace/pki"))

    results = []
    for root, python in ((bash_root, False), (python_root, True)):
        workspace = _workspace(root, isolated_environment, process_runner)
        _crash_writer(workspace, checkpoint)
        committed = _is_committed(workspace)
        if python:
            result = _python_recover(
                workspace,
                response_key=workspace.response_key if committed else None,
            )
        else:
            command: list[object] = [
                BASH_RECOVER,
                "--namespace",
                workspace.namespace,
                "--transaction",
                TRANSACTION,
                "--yes",
            ]
            if committed:
                command.extend(("--response-key", workspace.response_key))
            result = process_runner(
                command,
                env=environment(
                    isolated_environment,
                    PLATFORM_TOOLS_LIB_DIR=os.fspath(ORACLE_LIB),
                ),
                timeout=120,
            )
        results.append(result)

    def normalize_output(value: str) -> str:
        for root in (bash_root, python_root):
            value = value.replace(os.fspath(root), "<WORKSPACE>")
        return value

    def normalize_stderr(value: str) -> str:
        value = normalize_output(value)
        signing_prefix = (
            "<WORKSPACE>/namespace/pki/state/csr/transactions/"
            f"{TRANSACTION}/signing/response"
        )
        if value == (
            f"Signing file {signing_prefix}\n"
            f"Write signature to {signing_prefix}.sig\n"
        ):
            return ""
        return value

    assert (
        results[0].status,
        normalize_output(results[0].stdout),
        normalize_stderr(results[0].stderr),
    ) == (
        results[1].status,
        normalize_output(results[1].stdout),
        normalize_stderr(results[1].stderr),
    )
    openssl_normalizer = managed_openssl_dir_normalizer(
        seed, bash_root, python_root
    )

    def signing_normalizer(root: Path):
        signing = (
            root
            / "namespace/pki/state/csr/transactions"
            / TRANSACTION
            / "signing"
        )
        certificate = signing / "tls.crt"
        manifest = signing / "response"
        signature = signing / "response.sig"
        dynamic_digests: list[tuple[bytes, bytes]] = []
        certificate_bytes = certificate.read_bytes() if certificate.is_file() else b""
        if manifest.is_file():
            fields = dict(
                line.split("=", 1)
                for line in manifest.read_text(encoding="ascii").splitlines()
            )
            assert not certificate_bytes or fields["certificate_sha256"] == digest(
                certificate
            )
            dynamic_digests.append(
                (
                    fields["certificate_sha256"].encode("ascii"),
                    b"<CERTIFICATE-SHA256>",
                )
            )
            dynamic_digests.append(
                (digest(manifest).encode("ascii"), b"<RESPONSE-SHA256>")
            )
        if signature.is_file():
            dynamic_digests.append(
                (digest(signature).encode("ascii"), b"<RESPONSE-SIGNATURE-SHA256>")
            )
        encoded_roots = tuple(os.fsencode(value) for value in (bash_root, python_root))

        def normalize(relative: str, content: bytes) -> bytes:
            for encoded_root in encoded_roots:
                content = content.replace(encoded_root, b"<WORKSPACE>")
            if certificate_bytes:
                content = content.replace(
                    certificate_bytes,
                    b"<NONDETERMINISTIC-VALIDATED-LEAF-CERTIFICATE>\n",
                )
            if signature.is_file() and content == signature.read_bytes():
                content = b"<NONDETERMINISTIC-VALIDATED-RESPONSE-SIGNATURE>\n"
            for value, placeholder in dynamic_digests:
                content = re.sub(
                    rb"(?m)^(?P<field>[a-z0-9_]+)="
                    + re.escape(value)
                    + rb"$",
                    rb"\g<field>=" + placeholder,
                    content,
                )
            for field in (b"created_epoch", b"not_before_epoch", b"not_after_epoch"):
                content = re.sub(
                    rb"(?m)^" + field + rb"=\d+$",
                    field + b"=<" + field.upper().replace(b"_", b"-") + b">",
                    content,
                )
            if relative.endswith("/index.txt"):
                content = re.sub(
                    rb"(?m)^([VR]\t)\d{12}Z(\t)",
                    rb"\1<NOT-AFTER>\2",
                    content,
                )
            return content

        return normalize

    bash_normalizer = signing_normalizer(bash_root)
    python_normalizer = signing_normalizer(python_root)
    bash_snapshot = snapshot_state(
        bash_root / "namespace/pki", (openssl_normalizer, bash_normalizer)
    )
    python_snapshot = snapshot_state(
        python_root / "namespace/pki", (openssl_normalizer, python_normalizer)
    )
    if bash_snapshot != python_snapshot:
        for bash_entry, python_entry in zip(
            bash_snapshot, python_snapshot, strict=False
        ):
            if bash_entry == python_entry or bash_entry.path != python_entry.path:
                continue
            if bash_entry.kind == python_entry.kind == "file":
                relative = bash_entry.path
                bash_content = bash_normalizer(
                    relative, (bash_root / "namespace/pki" / relative).read_bytes()
                )
                python_content = python_normalizer(
                    relative, (python_root / "namespace/pki" / relative).read_bytes()
                )
                assert bash_content == python_content, relative
            break
    assert bash_snapshot == python_snapshot


def test_public_csr_recover_dispatch_is_python_owned() -> None:
    source = (REPOSITORY / "src/platform_pki/cli.py").read_text(encoding="ascii")
    assert "from .csr_recover import recover_csr" in source
    assert "return recover_csr" in source
    assert BASH_RECOVER.read_bytes().startswith(b"#!/usr/bin/env bash\n")
