from __future__ import annotations

import os
import re
import signal
import stat
import sys
import time
from collections.abc import Mapping
from pathlib import Path

import pytest

from src.platform_pki.csr_recovery import CSR_DB_KEYS, parse_signing_journal
from src.platform_pki.service_issue import CSR_SIGNING_WRITER_CHECKPOINTS, _valid_days_interval

from ..harness import ManagedProcess, ProcessResult, copy_tree, run_process
from .migration_harness import (
    run_differential_case,
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
from .test_csr_signing import (
    INVENTORY,
    ISSUE,
    CsrWorkspace,
    csr_workspace,
    run,
    tree_snapshot,
    write_csr,
    write_exchange,
)


pytestmark = pytest.mark.pki

REPOSITORY = Path(__file__).resolve().parents[2]
WRITER = REPOSITORY / "tests/pki/csr_issue_writer_driver.py"
RECOVER = REPOSITORY / "tests/pki/csr_signing_recover_driver.py"
ISSUE_ORACLE_ROOT = REPOSITORY / "tests/pki/oracles/platform-pki-service-issue"
ISSUE_ORACLE = ISSUE_ORACLE_ROOT / "platform-pki-service-issue"
ISSUE_ORACLE_LIB = ISSUE_ORACLE_ROOT / "lib"
REQUEST_ID = "0123456789abcdef0123456789abcdef"
TRANSACTION = f"csr-{REQUEST_ID}"


@pytest.mark.parametrize(
    ("actual", "accepted"),
    (
        (35 * 86400 - 1, False),
        (35 * 86400, True),
        (35 * 86400 + 1, True),
        (35 * 86400 + 300, True),
        (35 * 86400 + 301, False),
    ),
)
def test_planned_days_interval_allows_only_bounded_openssl_issuance_skew(
    actual: int, accepted: bool
) -> None:
    assert _valid_days_interval(1_000_000, 1_000_000 + actual, "35") is accepted


def _write(
    workspace: CsrWorkspace,
    *,
    env: Mapping[str, str] | None = None,
) -> ProcessResult:
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
            "--intermediate-pass-file",
            workspace.intermediate_pass,
        ],
        env=workspace.env if env is None else env,
        timeout=120,
    )


def _recover(workspace: CsrWorkspace, *, committed: bool) -> ProcessResult:
    command: list[object] = [
        sys.executable,
        RECOVER,
        "--pki-dir",
        workspace.pki,
        "--transaction",
        TRANSACTION,
    ]
    if committed:
        command.extend(("--response-key", workspace.response_key))
    return workspace.runner(command, env=workspace.env, timeout=120)


def _recover_with_environment(
    workspace: CsrWorkspace,
    *,
    committed: bool,
    env: Mapping[str, str],
) -> ProcessResult:
    command: list[object] = [
        sys.executable,
        RECOVER,
        "--pki-dir",
        workspace.pki,
        "--transaction",
        TRANSACTION,
    ]
    if committed:
        command.extend(("--response-key", workspace.response_key))
    return workspace.runner(command, env=env, timeout=120)


def _wait(path: Path, process: ManagedProcess, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    while not path.exists():
        observation = process.observe()
        if observation.status is not None:
            pytest.fail(f"process exited before pause marker: {observation}")
        if time.monotonic() >= deadline:
            pytest.fail(f"timed out waiting for pause marker: {path}")
        time.sleep(0.01)


def _start_paused_write(
    workspace: CsrWorkspace,
    process_starter,
    checkpoint: str,
) -> tuple[ManagedProcess, Path, Path]:
    marker = workspace.artifacts / f"{checkpoint}.pause"
    release = workspace.artifacts / f"{checkpoint}.release"
    process = process_starter(
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
            "--intermediate-pass-file",
            workspace.intermediate_pass,
        ],
        env=environment(
            workspace.env,
            PLATFORM_PKI_CSR_PYTHON_WRITER_PAUSE_AT=checkpoint,
            PLATFORM_PKI_CSR_PYTHON_WRITER_PAUSE_MARKER=os.fspath(marker),
            PLATFORM_PKI_CSR_PYTHON_WRITER_PAUSE_RELEASE=os.fspath(release),
        ),
        timeout=120,
    )
    return process, marker, release


def _copied_workspace(root: Path, env, runner) -> CsrWorkspace:
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


_CERTIFICATE_PEM = re.compile(
    rb"-----BEGIN CERTIFICATE-----\n.*?-----END CERTIFICATE-----\n?",
    re.DOTALL,
)
_DYNAMIC_DIGEST_FIELDS = (
    b"certificate_sha256",
    b"response_sha256",
    b"response_signature_sha256",
)


def _semantic_certificate(block: bytes) -> bytes:
    result = run_process(
        ("openssl", "x509", "-noout", "-text", "-nameopt", "RFC2253"),
        input=block,
    )
    assert_result(result, 0)
    text = result.stdout.encode("ascii")
    text = re.sub(
        rb"(?m)^(\s+Not Before:).*$", rb"\1 <NOT-BEFORE>", text
    )
    text = re.sub(rb"(?m)^(\s+Not After :).*$", rb"\1 <NOT-AFTER>", text)
    return re.sub(
        rb"(?m)^    Signature Value:\n(?:        [0-9a-f:]+\n?)+",
        b"    Signature Value:\n        <SIGNATURE>\n",
        text,
    )


def _csr_differential_content(relative: str, content: bytes) -> bytes:
    content = _CERTIFICATE_PEM.sub(
        lambda match: _semantic_certificate(match.group()), content
    )
    if relative.endswith("/response.sig"):
        return b"<VALIDATED-RESPONSE-SIGNATURE>\n"
    for field in _DYNAMIC_DIGEST_FIELDS:
        content = re.sub(
            rb"(?m)^" + field + rb"=[0-9a-f]{64}$",
            field + b"=<DYNAMIC-DIGEST>",
            content,
        )
    for field in (b"created_epoch", b"not_before_epoch", b"not_after_epoch"):
        content = re.sub(
            rb"(?m)^" + field + rb"=[0-9]+$",
            field + b"=<DYNAMIC-TIME>",
            content,
        )
    if relative.endswith("/index.txt"):
        content = re.sub(
            rb"(?m)^([VR]\t)[0-9]{12}Z(\t)", rb"\1<NOT-AFTER>\2", content
        )
    return content


def test_python_host_local_issue_publishes_only_protocol_artifacts(
    csr_workspace: CsrWorkspace,
) -> None:
    result = _write(csr_workspace)

    assert_result(result, 0)
    candidate = (
        csr_workspace.pki / f"state/csr/candidates/external/{REQUEST_ID}"
    )
    response = csr_workspace.pki / f"state/csr/responses/external/{REQUEST_ID}"
    assert sorted(path.name for path in candidate.iterdir()) == [
        "ca-chain.crt",
        "candidate",
        "fullchain.crt",
        "response",
        "response.sig",
        "tls.crt",
    ]
    assert sorted(path.name for path in response.iterdir()) == [
        "ca-chain.crt",
        "fullchain.crt",
        "response",
        "response.sig",
        "tls.crt",
    ]
    assert not list(candidate.rglob("*.key"))
    assert not (csr_workspace.pki / "services/external/private/tls.key").exists()
    assert not (csr_workspace.pki / "state/csr/recovery-journal").exists()


def test_final_bash_and_python_writers_publish_equivalent_protocol(
    tmp_path: Path,
    csr_workspace: CsrWorkspace,
    process_runner,
    isolated_environment,
) -> None:
    seed = csr_workspace.namespace.parent
    fixed = int(time.time())

    def workspace(root: Path, env: Mapping[str, str]) -> CsrWorkspace:
        return _copied_workspace(root, env, process_runner)

    def prepare(root: Path, env: Mapping[str, str]) -> None:
        write_exchange(
            workspace(root, env),
            "issue",
            REQUEST_ID,
            "ab" * 32,
            "none",
            request_created=fixed - 60,
            request_expires=fixed + 3600,
            approval_created=fixed - 30,
            approval_expires=fixed + 3600,
        )

    def bash_argv(root: Path) -> tuple[str | os.PathLike[str], ...]:
        value = workspace(root, {})
        return (
            ISSUE_ORACLE,
            "external",
            "--namespace",
            value.namespace,
            "--intermediate-pass-file",
            value.intermediate_pass,
            "--csr-file",
            value.artifacts / "tls.csr",
            "--request-file",
            value.artifacts / "request",
            "--request-signature",
            value.artifacts / "request.sig",
            "--approval-file",
            value.artifacts / "approval",
            "--approval-signature",
            value.artifacts / "approval.sig",
            "--response-key",
            value.response_key,
        )

    def python_argv(root: Path) -> tuple[str | os.PathLike[str], ...]:
        value = workspace(root, {})
        return (
            sys.executable,
            WRITER,
            "external",
            "--pki-dir",
            value.pki,
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
            "--intermediate-pass-file",
            value.intermediate_pass,
        )

    def normalize_output(root: Path, value: str) -> str:
        value = value.replace(os.fspath(root), "<WORKSPACE>")
        value = re.sub(
            r"(?m)^Signing file .*\nWrite signature to .*\n", "", value
        )
        return re.sub(
            r"(?m)^Certificate is to be certified until .* \(35 days\)$",
            "Certificate is to be certified until <NOT-AFTER> (35 days)",
            value,
        )

    result = run_differential_case(
        seed,
        tmp_path / "differential",
        Path("namespace/pki"),
        bash_argv,
        python_argv,
        dict(
            isolated_environment,
            PLATFORM_TOOLS_LIB_DIR=os.fspath(ISSUE_ORACLE_LIB),
        ),
        output_normalizers=(normalize_output,),
        content_normalizers=(_csr_differential_content,),
        run_options={"timeout": 120},
        bash_prepare=prepare,
        python_prepare=prepare,
        runner=process_runner,
    )

    result.assert_equivalent()
    assert CSR_DB_KEYS == (
        "index",
        "index_attr",
        "serial",
        "index_old",
        "index_attr_old",
        "serial_old",
        "newcert",
    )
    entries = {entry.path: entry for entry in result.python.after}
    for root, members in (
        (
            f"state/csr/candidates/external/{REQUEST_ID}",
            ("tls.crt", "ca-chain.crt", "fullchain.crt", "response", "response.sig", "candidate"),
        ),
        (
            f"state/csr/responses/external/{REQUEST_ID}",
            ("tls.crt", "ca-chain.crt", "fullchain.crt", "response", "response.sig"),
        ),
    ):
        assert entries[root].mode == 0o700
        for member in members:
            assert entries[f"{root}/{member}"].mode == 0o600


def test_python_host_local_migration_preserves_managed_service_state(
    csr_workspace: CsrWorkspace,
) -> None:
    managed_inventory = INVENTORY.replace(
        "    key_custody: host-local\n"
        "    target: host-01\n"
        "    validation_boundary_sha256: " + "0" * 64 + "\n"
        "    rollback_hold_seconds: 3600\n",
        "",
    )
    write_private(csr_workspace.pki / "inventory/services.yml", managed_inventory)
    managed = csr_workspace.runner(
        [
            *ISSUE,
            "external",
            "--namespace",
            csr_workspace.namespace,
            "--intermediate-pass-file",
            csr_workspace.intermediate_pass,
        ],
        env=csr_workspace.env,
        timeout=120,
    )
    assert_result(managed, 0)
    service_root = csr_workspace.pki / "services/external"
    certificate = service_root / "certs/tls.crt"
    before = tree_snapshot(service_root)
    write_private(csr_workspace.pki / "inventory/services.yml", INVENTORY)
    write_exchange(
        csr_workspace,
        "migrate",
        REQUEST_ID,
        "ab" * 32,
        digest(certificate),
    )

    result = _write(csr_workspace)

    assert_result(result, 0)
    assert tree_snapshot(service_root) == before
    assert (
        csr_workspace.pki / f"state/csr/candidates/external/{REQUEST_ID}"
    ).is_dir()


@pytest.mark.parametrize("checkpoint", CSR_SIGNING_WRITER_CHECKPOINTS)
def test_python_writer_crash_is_recovered_by_frozen_python_recovery(
    csr_workspace: CsrWorkspace,
    checkpoint: str,
) -> None:
    crashed = _write(
        csr_workspace,
        env=environment(
            csr_workspace.env,
            PLATFORM_PKI_CSR_PYTHON_WRITER_CRASH_AT=checkpoint,
        ),
    )
    assert crashed.status == 128 + signal.SIGKILL, (checkpoint, crashed)
    journal = csr_workspace.pki / "state/csr/recovery-journal"
    data = journal.read_bytes()
    record = parse_signing_journal(
        data,
        pki_dir=csr_workspace.pki,
        active_intermediate_dir=(
            csr_workspace.pki / "authorities/intermediates/g1-i1"
        ),
    )

    recovered = _recover(csr_workspace, committed=record.committed)

    assert_result(recovered, 0, stderr="")
    assert not journal.exists()
    assert (
        csr_workspace.pki / f"state/csr/replay/requests/{REQUEST_ID}"
    ).is_file()
    assert (
        csr_workspace.pki / f"state/csr/candidates/external/{REQUEST_ID}"
    ).is_dir() == record.committed


@pytest.mark.parametrize(
    ("checkpoint", "committed"),
    (
        ("signing-complete", False),
        ("after-ca-serial-publish", False),
        ("ca-committed", True),
    ),
)
def test_python_writer_signal_uses_commit_direction(
    csr_workspace: CsrWorkspace,
    checkpoint: str,
    committed: bool,
) -> None:
    result = _write(
        csr_workspace,
        env=environment(
            csr_workspace.env,
            PLATFORM_PKI_CSR_PYTHON_WRITER_SIGNAL_AT=checkpoint,
        ),
    )

    assert result.status == 128 + signal.SIGTERM
    journal = csr_workspace.pki / "state/csr/recovery-journal"
    assert journal.exists() == committed
    assert (
        csr_workspace.pki / f"state/csr/replay/requests/{REQUEST_ID}"
    ).is_file()
    if committed:
        recovered = _recover(csr_workspace, committed=True)
        assert_result(recovered, 0, stderr="")
    else:
        authority = csr_workspace.pki / "authorities/intermediates/g1-i1"
        assert (authority / "serial").read_text().strip() == "1000"
        assert not (authority / "newcerts/1000.pem").exists()


def test_python_writer_rejects_unauthenticated_request_without_consuming_replay(
    csr_workspace: CsrWorkspace,
) -> None:
    signature = csr_workspace.artifacts / "request.sig"
    signature.write_bytes(signature.read_bytes().replace(b"U1NI", b"V1NI", 1))

    result = _write(csr_workspace)

    assert result.status == 1
    assert "signature verification failed" in result.stderr
    assert not (csr_workspace.pki / "state/csr/recovery-journal").exists()
    assert not (
        csr_workspace.pki / f"state/csr/replay/requests/{REQUEST_ID}"
    ).exists()
    assert (
        csr_workspace.pki / "authorities/intermediates/g1-i1/serial"
    ).read_text().strip() == "1000"


@pytest.mark.parametrize(
    "case",
    ("policy", "options", "algorithm", "malformed-key"),
)
def test_python_writer_rejects_malformed_installed_trust_before_replay(
    csr_workspace: CsrWorkspace,
    case: str,
) -> None:
    trust = csr_workspace.pki / "inventory/csr-trust"
    if case == "policy":
        path = trust / "policy"
        path.write_text(
            path.read_text(encoding="ascii").replace(
                "clock_skew_seconds=300", "clock_skew_seconds=301"
            ),
            encoding="ascii",
        )
    else:
        path = trust / "requesters.allowed_signers"
        fields = path.read_text(encoding="ascii").strip().split()
        if case == "options":
            fields.insert(0, "restrict")
        elif case == "algorithm":
            fields[1] = "ssh-rsa"
        else:
            fields[2] = "not-a-base64-key@"
        path.write_text(" ".join(fields) + "\n", encoding="ascii")
    path.chmod(0o600)

    result = _write(csr_workspace)

    assert result.status == 1
    assert "Installed CSR" in result.stderr
    assert not (csr_workspace.pki / "state/csr/recovery-journal").exists()
    assert not (
        csr_workspace.pki / f"state/csr/replay/requests/{REQUEST_ID}"
    ).exists()


@pytest.mark.parametrize("kind", ("directory", "extra-entry"))
def test_python_writer_rechecks_exact_trust_tree_before_journaling(
    csr_workspace: CsrWorkspace,
    process_starter,
    kind: str,
) -> None:
    process, marker, release = _start_paused_write(
        csr_workspace, process_starter, "trust-before-journal-recheck"
    )
    trust = csr_workspace.pki / "inventory/csr-trust"
    with process:
        _wait(marker, process)
        if kind == "directory":
            saved = trust.with_name("csr-trust.saved")
            trust.rename(saved)
            trust.mkdir(mode=0o700)
            for source in saved.iterdir():
                os.link(source, trust / source.name)
        else:
            write_private(trust / "unexpected", "unexpected trust state\n")
        release.touch(mode=0o600)
        result = process.wait()

    assert result.status == 1
    assert "trust directory" in result.stderr
    assert not (csr_workspace.pki / "state/csr/recovery-journal").exists()
    assert not (
        csr_workspace.pki / f"state/csr/replay/requests/{REQUEST_ID}"
    ).exists()


def _replace_same_bytes(path: Path) -> None:
    replacement = path.with_name(f".{path.name}.replacement")
    replacement.write_bytes(path.read_bytes())
    replacement.chmod(path.stat().st_mode & 0o777)
    os.replace(replacement, path)


def _semantic_ca_database_state(authority: Path) -> tuple[tuple[str, int, str], ...]:
    result = []
    for relative in (
        "index.txt",
        "index.txt.attr",
        "serial",
        "index.txt.old",
        "index.txt.attr.old",
        "serial.old",
    ):
        path = authority / relative
        if path.exists() and not path.is_symlink():
            result.append((relative, stat.S_IMODE(path.stat().st_mode), digest(path)))
    newcerts = authority / "newcerts"
    for path in sorted(newcerts.iterdir()):
        result.append(
            (
                path.relative_to(authority).as_posix(),
                stat.S_IMODE(path.stat().st_mode),
                digest(path),
            )
        )
    return tuple(result)


def _foreign_state(path: Path) -> object:
    metadata = path.lstat()
    prefix = (
        stat.S_IFMT(metadata.st_mode) | stat.S_IMODE(metadata.st_mode),
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_ino,
    )
    if path.is_dir() and not path.is_symlink():
        return prefix, tree_snapshot(path)
    return prefix, metadata.st_size, metadata.st_mtime_ns, digest(path)


def _replace_preserving_original(path: Path, label: str) -> Path:
    saved = path.with_name(f".{path.name}.{label}.original")
    path.rename(saved)
    if saved.is_dir():
        copy_tree(saved, path)
    else:
        path.write_bytes(saved.read_bytes())
        path.chmod(stat.S_IMODE(saved.stat().st_mode))
    return saved


@pytest.mark.parametrize(
    ("checkpoint", "source"),
    (
        ("source-before-journal-recheck", "request"),
        ("trust-before-sensitive-staging", "ca-key"),
        ("source-before-ca-publication", "inventory"),
    ),
)
def test_python_writer_rejects_authenticated_source_replacement_races(
    csr_workspace: CsrWorkspace,
    process_starter,
    checkpoint: str,
    source: str,
) -> None:
    paths = {
        "request": csr_workspace.artifacts / "request",
        "ca-key": (
            csr_workspace.pki
            / "authorities/intermediates/g1-i1/private/intermediate-ca.key"
        ),
        "inventory": csr_workspace.pki / "inventory/services.yml",
    }
    process, marker, release = _start_paused_write(
        csr_workspace, process_starter, checkpoint
    )
    with process:
        _wait(marker, process)
        _replace_same_bytes(paths[source])
        release.touch(mode=0o600)
        result = process.wait()

    assert result.status == 1
    assert not (
        csr_workspace.pki / f"state/csr/candidates/external/{REQUEST_ID}"
    ).exists()
    if source == "request":
        assert not (csr_workspace.pki / "state/csr/recovery-journal").exists()
    else:
        assert (
            csr_workspace.pki / f"state/csr/replay/requests/{REQUEST_ID}"
        ).is_file()


@pytest.mark.parametrize(
    "source",
    (
        "root-directory",
        "intermediate-directory",
        "root-certificate",
        "intermediate-key",
        "intermediate-certificate",
        "intermediate-config",
        "crlnumber",
        "active-issuer",
        "inventory",
        "trust-directory",
        "trust-policy",
        "trust-requesters",
        "trust-approvers",
        "trust-responses",
    ),
)
def test_prepublication_authority_replacements_retain_recoverable_journal(
    csr_workspace: CsrWorkspace,
    process_starter,
    source: str,
) -> None:
    root = csr_workspace.pki / "authorities/roots/g1"
    intermediate = csr_workspace.pki / "authorities/intermediates/g1-i1"
    trust = csr_workspace.pki / "inventory/csr-trust"
    paths = {
        "root-directory": root,
        "intermediate-directory": intermediate,
        "root-certificate": root / "certs/root-ca.crt",
        "intermediate-key": intermediate / "private/intermediate-ca.key",
        "intermediate-certificate": intermediate / "certs/intermediate-ca.crt",
        "intermediate-config": intermediate / "openssl.cnf",
        "crlnumber": intermediate / "crlnumber",
        "active-issuer": csr_workspace.pki / "state/active-issuer",
        "inventory": csr_workspace.pki / "inventory/services.yml",
        "trust-directory": trust,
        "trust-policy": trust / "policy",
        "trust-requesters": trust / "requesters.allowed_signers",
        "trust-approvers": trust / "approvers.allowed_signers",
        "trust-responses": trust / "responses.allowed_signers",
    }
    process, marker, release = _start_paused_write(
        csr_workspace, process_starter, "source-before-ca-publication"
    )
    with process:
        _wait(marker, process)
        before_database = _semantic_ca_database_state(intermediate)
        path = paths[source]
        saved = _replace_preserving_original(path, source)
        foreign_before = _foreign_state(path)
        release.touch(mode=0o600)
        result = process.wait()

    assert result.status == 1
    assert _semantic_ca_database_state(intermediate) == before_database
    assert _foreign_state(path) == foreign_before
    journal = csr_workspace.pki / "state/csr/recovery-journal"
    record = parse_signing_journal(
        journal.read_bytes(),
        pki_dir=csr_workspace.pki,
        active_intermediate_dir=intermediate,
    )
    assert not record.committed
    assert not (intermediate / "newcerts/1000.pem").exists()

    foreign = csr_workspace.artifacts / f"foreign-{source}"
    path.rename(foreign)
    saved.rename(path)
    recovered = _recover(csr_workspace, committed=False)

    assert_result(recovered, 0, stderr="")
    assert not journal.exists()
    assert _foreign_state(foreign) == foreign_before


@pytest.mark.parametrize("case", ("wrong-curve", "wrong-signature", "attribute"))
def test_python_writer_rejects_csr_key_signature_and_attribute_profiles(
    csr_workspace: CsrWorkspace,
    case: str,
) -> None:
    if case == "wrong-curve":
        csr_workspace.host_key.unlink()
        assert_result(
            run(
                csr_workspace.runner,
                (
                    "openssl",
                    "genpkey",
                    "-algorithm",
                    "EC",
                    "-pkeyopt",
                    "ec_paramgen_curve:prime256v1",
                    "-out",
                    csr_workspace.host_key,
                ),
                csr_workspace.env,
            ),
            0,
        )
        csr_workspace.host_key.chmod(0o600)
        write_csr(csr_workspace)
    elif case == "wrong-signature":
        write_csr(csr_workspace, digest_name="sha256")
    else:
        write_csr(csr_workspace, attributes=("challengePassword = challenge",))

    result = _write(csr_workspace)

    assert result.status == 1
    assert not (csr_workspace.pki / "state/csr/recovery-journal").exists()
    assert not (
        csr_workspace.pki / f"state/csr/replay/requests/{REQUEST_ID}"
    ).exists()


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        ("duplicate", "duplicate subjectAltName"),
        ("empty", "invalid subjectAltName entry"),
        ("prefix", "invalid subjectAltName entry"),
        ("extra", "subjectAltName set does not match"),
    ),
)
def test_python_writer_rejects_duplicate_empty_prefixed_or_extra_sans(
    csr_workspace: CsrWorkspace,
    executable_directory: Path,
    mutation: str,
    message: str,
) -> None:
    real_openssl = executable("openssl")
    fake = executable_directory / "openssl-san"
    marker = csr_workspace.artifacts / "openssl-san-invocations.log"
    write_executable(
        fake / "openssl",
        """#!/usr/bin/env bash
set -euo pipefail
printf '<%s>\n' "$@" >>"$OPENSSL_INTERCEPT_LOG"
if [[ ${1:-} == req && " $* " == *' -text '* ]]; then
  output=$("$REAL_OPENSSL" "$@")
  case $SAN_MUTATION in
    duplicate) output=${output/DNS:external, IP Address:/DNS:external, DNS:external, IP Address:} ;;
    empty) output=${output/DNS:external, IP Address:/DNS:, IP Address:} ;;
    prefix) output=${output/DNS:external, IP Address:/URI:external, IP Address:} ;;
    extra) output=${output/DNS:external, IP Address:/DNS:external, DNS:extra.internal, IP Address:} ;;
  esac
  printf '%s\n' "$output"
  exit 0
fi
exec "$REAL_OPENSSL" "$@"
""",
    )

    result = _write(
        csr_workspace,
        env=environment(
            csr_workspace.env,
            PATH=f"{fake}{os.pathsep}{csr_workspace.env['PATH']}",
            REAL_OPENSSL=real_openssl,
            OPENSSL_INTERCEPT_LOG=os.fspath(marker),
            SAN_MUTATION=mutation,
        ),
    )

    assert marker.is_file()
    invocations = marker.read_text(encoding="ascii")
    assert "<req>" in invocations and "<-text>" in invocations
    assert result.status == 1
    assert message in result.stderr
    assert not (csr_workspace.pki / "state/csr/recovery-journal").exists()


@pytest.mark.parametrize(
    ("mode", "message"),
    (
        ("success", None),
        ("lifetime", "validity does not match the planned days policy"),
        ("not-before", "notBefore is outside the five-minute issuance tolerance"),
    ),
)
def test_python_writer_runs_ca_once_and_enforces_issued_certificate_time_policy(
    csr_workspace: CsrWorkspace,
    executable_directory: Path,
    mode: str,
    message: str | None,
) -> None:
    real_openssl = executable("openssl")
    fake = executable_directory / "openssl-policy"
    log = csr_workspace.artifacts / "openssl-ca.log"
    marker = csr_workspace.artifacts / "openssl-policy-invocations.log"
    write_executable(
        fake / "openssl",
        """#!/usr/bin/env bash
set -euo pipefail
printf '<%s>\n' "$@" >>"$OPENSSL_INTERCEPT_LOG"
if [[ ${1:-} == ca ]]; then
  printf 'ca\n' >>"$OPENSSL_CA_LOG"
  arguments=("$@")
  if [[ $OPENSSL_POLICY_MODE == lifetime ]]; then
    for ((index=0; index < ${#arguments[@]}; index++)); do
      if [[ ${arguments[index]} == -days ]]; then arguments[index + 1]=1; fi
    done
  fi
  exec "$REAL_OPENSSL" "${arguments[@]}"
fi
if [[ $OPENSSL_POLICY_MODE == not-before && ${1:-} == x509 && " $* " == *' -dates '* && " $* " != *' -subject '* && " $* " == *'/signing/tls.crt '* ]]; then
  "$REAL_OPENSSL" "$@" | sed 's/^notBefore=.*/notBefore=Jan  1 00:00:00 2000 GMT/'
  exit 0
fi
exec "$REAL_OPENSSL" "$@"
""",
    )
    result = _write(
        csr_workspace,
        env=environment(
            csr_workspace.env,
            PATH=f"{fake}{os.pathsep}{csr_workspace.env['PATH']}",
            REAL_OPENSSL=real_openssl,
            OPENSSL_CA_LOG=os.fspath(log),
            OPENSSL_INTERCEPT_LOG=os.fspath(marker),
            OPENSSL_POLICY_MODE=mode,
        ),
    )

    assert marker.is_file()
    invocations = marker.read_text(encoding="ascii")
    assert "<ca>" in invocations
    assert log.read_text(encoding="ascii").splitlines() == ["ca"]
    if message is None:
        assert_result(result, 0)
    else:
        assert result.status == 1
        assert message in result.stderr
        assert not (csr_workspace.pki / "state/csr/recovery-journal").exists()
        assert (
            csr_workspace.pki / "authorities/intermediates/g1-i1/serial"
        ).read_text().strip() == "1000"


def test_python_writer_response_is_not_created_before_certificate(
    csr_workspace: CsrWorkspace,
    executable_directory: Path,
) -> None:
    real_openssl = executable("openssl")
    fake = executable_directory / "openssl-created-epoch"
    write_executable(
        fake / "openssl",
        """#!/usr/bin/env bash
set -euo pipefail
if [[ ${1:-} == ca ]]; then
  created=
  while IFS='=' read -r name value; do
    if [[ $name == created_epoch ]]; then created=$value; break; fi
  done <"$PKI_TEST_DIR/state/csr/recovery-journal"
  while (( $(date +%s) <= created )); do sleep 0.05; done
fi
exec "$REAL_OPENSSL" "$@"
""",
    )

    result = _write(
        csr_workspace,
        env=environment(
            csr_workspace.env,
            PATH=f"{fake}{os.pathsep}{csr_workspace.env['PATH']}",
            PKI_TEST_DIR=os.fspath(csr_workspace.pki),
            REAL_OPENSSL=real_openssl,
        ),
    )

    assert_result(result, 0)
    candidate = dict(
        line.split("=", 1)
        for line in (
            csr_workspace.pki
            / f"state/csr/candidates/external/{REQUEST_ID}/candidate"
        ).read_text(encoding="ascii").splitlines()
    )
    response = dict(
        line.split("=", 1)
        for line in (
            csr_workspace.pki
            / f"state/csr/responses/external/{REQUEST_ID}/response"
        ).read_text(encoding="ascii").splitlines()
    )
    assert int(response["not_before_epoch"]) > int(candidate["created_epoch"])
    assert response["created_epoch"] == response["not_before_epoch"]


def test_python_writer_rejects_request_and_nonce_replay_retries(
    csr_workspace: CsrWorkspace,
) -> None:
    assert_result(_write(csr_workspace), 0)

    request_retry = _write(csr_workspace)
    assert request_retry.status == 1
    assert "request ID has already been consumed" in request_retry.stderr
    write_exchange(
        csr_workspace,
        "issue",
        "1123456789abcdef0123456789abcdef",
        "ab" * 32,
        "none",
    )
    nonce_retry = _write(csr_workspace)
    assert nonce_retry.status == 1
    assert "request nonce has already been consumed" in nonce_retry.stderr
    assert (
        csr_workspace.pki / "authorities/intermediates/g1-i1/serial"
    ).read_text().strip() == "1001"


def _openssl_count_environment(
    workspace: CsrWorkspace,
    executable_directory: Path,
    **values: str,
) -> tuple[dict[str, str], Path, Path]:
    real_openssl = executable("openssl")
    fake = executable_directory / "openssl-count"
    log = workspace.artifacts / "openssl-ca-count.log"
    marker = workspace.artifacts / "openssl-count-invocations.log"
    write_executable(
        fake / "openssl",
        """#!/usr/bin/env bash
set -euo pipefail
printf '<%s>\n' "$@" >>"$OPENSSL_INTERCEPT_LOG"
if [[ ${1:-} == ca ]]; then printf 'ca\n' >>"$OPENSSL_CA_LOG"; fi
exec "$REAL_OPENSSL" "$@"
""",
    )
    return (
        environment(
            workspace.env,
            PATH=f"{fake}{os.pathsep}{workspace.env['PATH']}",
            REAL_OPENSSL=real_openssl,
            OPENSSL_CA_LOG=os.fspath(log),
            OPENSSL_INTERCEPT_LOG=os.fspath(marker),
            **values,
        ),
        log,
        marker,
    )


@pytest.mark.parametrize("injection", ("signal", "failure"))
def test_durable_commit_gap_never_rolls_back_or_resigns_ca(
    csr_workspace: CsrWorkspace,
    executable_directory: Path,
    injection: str,
) -> None:
    variable = (
        "PLATFORM_PKI_CSR_PYTHON_WRITER_SIGNAL_AT"
        if injection == "signal"
        else "PLATFORM_PKI_CSR_PYTHON_WRITER_FAILURE_AT"
    )
    env, log, marker = _openssl_count_environment(
        csr_workspace,
        executable_directory,
        **{variable: "ca-commit-after-journal-rewrite"},
    )
    interrupted = _write(csr_workspace, env=env)
    assert marker.is_file()
    assert "<ca>" in marker.read_text(encoding="ascii")
    assert interrupted.status == (
        128 + signal.SIGTERM if injection == "signal" else 1
    )
    journal = csr_workspace.pki / "state/csr/recovery-journal"
    record = parse_signing_journal(
        journal.read_bytes(),
        pki_dir=csr_workspace.pki,
        active_intermediate_dir=(
            csr_workspace.pki / "authorities/intermediates/g1-i1"
        ),
    )
    assert record.committed
    authority = csr_workspace.pki / "authorities/intermediates/g1-i1"
    committed_state = tree_snapshot(authority)

    recovered = _recover_with_environment(
        csr_workspace,
        committed=True,
        env=environment(
            env,
            **{variable: ""},
        ),
    )

    assert_result(recovered, 0, stderr="")
    assert tree_snapshot(authority) == committed_state
    assert log.read_text(encoding="ascii").splitlines() == ["ca"]


def test_failure_hook_rolls_back_precommit_and_permanently_consumes_replay(
    csr_workspace: CsrWorkspace,
) -> None:
    failed = _write(
        csr_workspace,
        env=environment(
            csr_workspace.env,
            PLATFORM_PKI_CSR_PYTHON_WRITER_FAILURE_AT="after-ca-serial-publish",
        ),
    )

    assert failed.status == 1
    assert not (csr_workspace.pki / "state/csr/recovery-journal").exists()
    assert (
        csr_workspace.pki / "authorities/intermediates/g1-i1/serial"
    ).read_text().strip() == "1000"
    assert (
        csr_workspace.pki / f"state/csr/replay/requests/{REQUEST_ID}"
    ).is_file()
    retry = _write(csr_workspace)
    assert retry.status == 1
    assert "request ID has already been consumed" in retry.stderr


def _response_signature_count_environment(
    workspace: CsrWorkspace,
    executable_directory: Path,
) -> tuple[dict[str, str], Path, str]:
    real_ssh_keygen = executable("ssh-keygen")
    fake = executable_directory / "ssh-keygen-count"
    log = workspace.artifacts / "response-sign-count.log"
    write_executable(
        fake / "ssh-keygen",
        """#!/usr/bin/env bash
set -euo pipefail
if [[ " $* " == *' -Y sign '* ]]; then printf 'sign\n' >>"$SSH_SIGN_LOG"; fi
if [[ " $* " == *' -Y verify '* && " $* " == *' platform-pki-csr-response-v1 '* ]]; then printf 'verify\n' >>"$SSH_SIGN_LOG"; fi
exec "$REAL_SSH_KEYGEN" "$@"
""",
    )
    return (
        environment(
            workspace.env,
            PATH=f"{fake}{os.pathsep}{workspace.env['PATH']}",
            REAL_SSH_KEYGEN=real_ssh_keygen,
            SSH_SIGN_LOG=os.fspath(log),
        ),
        log,
        real_ssh_keygen,
    )


def test_response_signature_mutation_restart_does_not_sign_twice(
    csr_workspace: CsrWorkspace,
    executable_directory: Path,
) -> None:
    base, log, _real_ssh_keygen = _response_signature_count_environment(
        csr_workspace, executable_directory
    )
    crashed = _write(
        csr_workspace,
        env=environment(
            base,
            PLATFORM_PKI_CSR_PYTHON_WRITER_CRASH_AT=(
                "response-signature-after-mutation"
            ),
        ),
    )
    assert crashed.status == 128 + signal.SIGKILL

    recovered = _recover_with_environment(
        csr_workspace,
        committed=True,
        env=base,
    )

    assert_result(recovered, 0, stderr="")
    assert log.is_file()
    assert log.read_text(encoding="ascii").splitlines() == ["sign", "verify"]


@pytest.mark.parametrize("case", ("malformed", "unsafe-mode", "hardlink"))
def test_owned_response_signature_window_rejects_invalid_signature_state(
    csr_workspace: CsrWorkspace,
    executable_directory: Path,
    case: str,
) -> None:
    base, log, _real_ssh_keygen = _response_signature_count_environment(
        csr_workspace, executable_directory
    )
    crashed = _write(
        csr_workspace,
        env=environment(
            base,
            PLATFORM_PKI_CSR_PYTHON_WRITER_CRASH_AT=(
                "response-signature-after-mutation"
            ),
        ),
    )
    assert crashed.status == 128 + signal.SIGKILL
    signature = (
        csr_workspace.pki
        / f"state/csr/transactions/{TRANSACTION}/signing/response.sig"
    )
    if case == "malformed":
        signature.write_bytes(b"not an OpenSSH signature\n")
        signature.chmod(0o600)
    elif case == "unsafe-mode":
        signature.chmod(0o666)
    else:
        os.link(signature, csr_workspace.artifacts / "foreign-response-signature")

    recovered = _recover_with_environment(
        csr_workspace,
        committed=True,
        env=base,
    )

    assert recovered.status == 1
    assert (csr_workspace.pki / "state/csr/recovery-journal").is_file()
    assert not (
        csr_workspace.pki / f"state/csr/candidates/external/{REQUEST_ID}"
    ).exists()
    invocations = log.read_text(encoding="ascii").splitlines()
    assert invocations.count("sign") == 1
    assert invocations.count("verify") == (1 if case == "malformed" else 0)


def test_owned_response_signature_replacement_after_authentication_fails_closed(
    csr_workspace: CsrWorkspace,
    executable_directory: Path,
    process_starter,
) -> None:
    base, log, _real_ssh_keygen = _response_signature_count_environment(
        csr_workspace, executable_directory
    )
    crashed = _write(
        csr_workspace,
        env=environment(
            base,
            PLATFORM_PKI_CSR_PYTHON_WRITER_CRASH_AT=(
                "response-signature-after-mutation"
            ),
        ),
    )
    assert crashed.status == 128 + signal.SIGKILL
    marker = csr_workspace.artifacts / "response-signature-authenticated"
    release = csr_workspace.artifacts / "response-signature-authenticated-release"
    process = process_starter(
        (
            sys.executable,
            RECOVER,
            "--pki-dir",
            csr_workspace.pki,
            "--transaction",
            TRANSACTION,
            "--response-key",
            csr_workspace.response_key,
        ),
        env=environment(
            base,
            PLATFORM_PKI_CSR_PYTHON_RECOVER_PAUSE_AT=(
                "response-signature-before-evidence"
            ),
            PLATFORM_PKI_CSR_PYTHON_RECOVER_PAUSE_MARKER=os.fspath(marker),
            PLATFORM_PKI_CSR_PYTHON_RECOVER_PAUSE_RELEASE=os.fspath(release),
        ),
        timeout=120,
    )
    signature = (
        csr_workspace.pki
        / f"state/csr/transactions/{TRANSACTION}/signing/response.sig"
    )
    with process:
        _wait(marker, process)
        _replace_same_bytes(signature)
        release.touch(mode=0o600)
        result = process.wait()

    assert result.status == 1
    assert "identity changed before evidence" in result.stderr
    assert log.read_text(encoding="ascii").splitlines() == ["sign", "verify"]
    record = parse_signing_journal(
        (csr_workspace.pki / "state/csr/recovery-journal").read_bytes(),
        pki_dir=csr_workspace.pki,
        active_intermediate_dir=(
            csr_workspace.pki / "authorities/intermediates/g1-i1"
        ),
    )
    assert record.recovery_step.value == "response-signing"
    assert record["response_signature_identity"] == "none"


def test_unowned_final_bash_signature_is_recreated_instead_of_adopted(
    csr_workspace: CsrWorkspace,
    executable_directory: Path,
) -> None:
    base, log, real_ssh_keygen = _response_signature_count_environment(
        csr_workspace, executable_directory
    )
    crashed = _write(
        csr_workspace,
        env=environment(
            csr_workspace.env,
            PLATFORM_PKI_CSR_PYTHON_WRITER_CRASH_AT="ca-committed",
        ),
    )
    assert crashed.status == 128 + signal.SIGKILL
    signing = csr_workspace.pki / f"state/csr/transactions/{TRANSACTION}/signing"
    manifest = signing / "response"
    manual = csr_workspace.runner(
        (
            real_ssh_keygen,
            "-Y",
            "sign",
            "-f",
            csr_workspace.response_key,
            "-n",
            "platform-pki-csr-response-v1",
            manifest,
        ),
        env=csr_workspace.env,
        timeout=120,
    )
    assert_result(manual, 0)
    signature = signing / "response.sig"
    signature.chmod(0o600)
    with signature.open("rb") as unowned:
        unowned_inode = os.fstat(unowned.fileno()).st_ino
        recovered = _recover_with_environment(
            csr_workspace,
            committed=True,
            env=base,
        )

        assert_result(recovered, 0, stderr="")
        assert signature.stat().st_ino != unowned_inode
    assert log.read_text(encoding="ascii").splitlines() == ["sign", "verify"]


def test_writer_detects_response_key_replacement_before_publication(
    csr_workspace: CsrWorkspace,
    process_starter,
) -> None:
    process, marker, release = _start_paused_write(
        csr_workspace, process_starter, "response-signature-before-mutation"
    )
    with process:
        _wait(marker, process)
        _replace_same_bytes(csr_workspace.response_key)
        release.touch(mode=0o600)
        result = process.wait()

    assert result.status == 1
    assert "Response signing key changed during signing" in result.stderr
    assert (csr_workspace.pki / "state/csr/recovery-journal").is_file()
    assert not (
        csr_workspace.pki / f"state/csr/candidates/external/{REQUEST_ID}"
    ).exists()
