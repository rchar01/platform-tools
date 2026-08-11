from __future__ import annotations

import os
import re
import shutil
import signal
import sys
import time
from collections.abc import Callable
from pathlib import Path

import pytest

from ..harness import ManagedProcess, ProcessResult
from .create_test_support import (
    CreateWorkspace,
    assert_passphrase_content_absent,
    digest,
    environment,
    mode,
    openssl,
    ready_ca,
    require_success,
    run,
    tools,
    workspace,
)
from src.platform_pki.service_transaction import (
    SERVICE_TRANSACTION_FIELDS,
    parse_service_transaction,
)


pytestmark = pytest.mark.pki
REPOSITORY = Path(__file__).resolve().parents[2]
DRIVER = REPOSITORY / "tests/pki/service_issue_writer_driver.py"
INVENTORY = """services:
  app:
    common_name: app.example.internal
    dns:
      - app.example.internal
      - app
    ips:
      - 192.0.2.10
    days: 35
  rotate:
    common_name: rotate.example.internal
    dns:
      - rotate.example.internal
    ips:
      - 192.0.2.11
  reuse:
    common_name: reuse.example.internal
    dns:
      - reuse.example.internal
  default:
    common_name: default.example.internal
    dns:
      - default.example.internal
  external:
    key_custody: host-local
    target: host-01
    validation_boundary_sha256: 0000000000000000000000000000000000000000000000000000000000000000
    rollback_hold_seconds: 3600
    common_name: external.example.internal
    dns:
      - external.example.internal
"""


def _python_issue(value, service: str, *arguments: str | Path) -> list[str | Path]:
    return [
        sys.executable,
        DRIVER,
        service,
        "--pki-dir",
        value.pki,
        "--intermediate-pass-file",
        value.intermediate_pass,
        *arguments,
    ]


def _clone_workspace(seed: CreateWorkspace, root: Path) -> CreateWorkspace:
    shutil.copytree(seed.root, root, copy_function=shutil.copy2)
    value = CreateWorkspace(
        root,
        root / "namespace",
        root / "namespace/pki",
        root / "root.pass",
        root / "intermediate.pass",
    )
    for relative in (
        "authorities/roots/g1/openssl.cnf",
        "authorities/intermediates/g1-i1/openssl.cnf",
    ):
        config = value.pki / relative
        data = config.read_bytes().replace(
            os.fsencode(seed.pki), os.fsencode(value.pki)
        )
        config.write_bytes(data)
        config.chmod(0o600)
    # The authenticated terminal bootstrap record binds the original absolute tree.
    (value.pki / "state/rollover/journal").unlink(missing_ok=True)
    return value


def _transaction(value: CreateWorkspace) -> str:
    journal = value.pki / "state/service/recovery-journal"
    return parse_service_transaction(journal.read_bytes(), pki_dir=value.pki)[
        "transaction"
    ]


def _recover(value: CreateWorkspace) -> list[str | Path]:
    return [
        sys.executable,
        REPOSITORY / "tests/pki/service_recover_driver.py",
        "--pki-dir",
        value.pki,
        "--transaction",
        _transaction(value),
    ]


def _bootstrap_transaction(value: CreateWorkspace) -> str:
    journal = value.pki / "state/service/recovery-journal"
    if journal.is_file():
        return parse_service_transaction(journal.read_bytes(), pki_dir=value.pki)[
            "transaction"
        ]
    bootstrap = value.pki / "state/service/bootstrap"
    if bootstrap.is_file():
        fields = dict(
            line.split("=", 1) for line in bootstrap.read_text().splitlines()
        )
        return fields["transaction"]
    stages = tuple((value.pki / "state/service").glob(".service-*.bootstrap.publish"))
    if stages:
        assert len(stages) == 1
        return stages[0].name.removeprefix(".").removesuffix(".bootstrap.publish")
    history = tuple((value.pki / "state/service/bootstrap-history").iterdir())
    assert len(history) == 1
    return history[0].name


def _recover_exact(value: CreateWorkspace, transaction: str) -> list[str | Path]:
    return [
        sys.executable,
        REPOSITORY / "tests/pki/service_recover_driver.py",
        "--pki-dir",
        value.pki,
        "--transaction",
        transaction,
    ]


def _assert_failed_transaction_clean(value: CreateWorkspace) -> None:
    assert not (value.pki / "state/service/recovery-journal").exists()
    transactions = tuple((value.pki / "state/service/transactions").iterdir())
    assert len(transactions) == 1
    assert (transactions[0] / "terminal").is_file()
    assert not (transactions[0] / "stage").exists()
    assert not (transactions[0] / "backup").exists()
    assert not (value.pki / "services/app/certs/tls.crt").exists()


def _ca_state(value: CreateWorkspace) -> tuple[tuple[str, int, bytes], ...]:
    authority = value.pki / "authorities/intermediates/g1-i1"
    return tuple(
        (path.relative_to(authority).as_posix(), mode(path), path.read_bytes())
        for path in sorted(authority.rglob("*"))
        if path.is_file() and not path.is_symlink()
    )


def _normalize_signing_stderr(value: CreateWorkspace, content: str) -> str:
    normalized = content.replace(os.fspath(value.pki), "<PKI>")
    normalized = re.sub(
        r"^Using configuration from .+$",
        "Using configuration from <CONFIG>",
        normalized,
        flags=re.MULTILINE,
    )
    return re.sub(
        r"^Certificate is to be certified until .+ \(([0-9]+ days)\)$",
        r"Certificate is to be certified until <EXPIRY> (\1)",
        normalized,
        flags=re.MULTILINE,
    )


def _semantic_state(value: CreateWorkspace) -> dict[str, object]:
    authority = value.pki / "authorities/intermediates/g1-i1"
    service = value.pki / "services/app"
    result: dict[str, object] = {}
    for relative in (
        "openssl.cnf",
        "issuer",
        "chain/ca-chain.crt",
        "certs/tls.crt",
        "csr/tls.csr",
        "private/tls.key",
        "chain/fullchain.crt",
    ):
        path = service / relative
        result[f"service:{relative}"] = (mode(path), path.stat().st_nlink)
    for name in (
        "index.txt.attr",
        "serial",
        "index.txt.old",
        "index.txt.attr.old",
        "serial.old",
    ):
        path = authority / name
        result[f"ca:{name}"] = (mode(path), path.read_bytes())
    index_fields = (authority / "index.txt").read_text().strip().split("\t")
    result["ca:index"] = (
        index_fields[0],
        index_fields[2],
        index_fields[3],
        index_fields[4],
        index_fields[5],
    )
    result["newcert-names"] = tuple(
        path.name for path in sorted((authority / "newcerts").iterdir())
    )
    result["newcert-mode"] = mode(authority / "newcerts/1000.pem")
    result["newcert-equals-service"] = (
        (authority / "newcerts/1000.pem").read_bytes()
        == (service / "certs/tls.crt").read_bytes()
    )
    result["config"] = (service / "openssl.cnf").read_bytes()
    result["issuer"] = (service / "issuer").read_bytes()
    result["chain"] = (service / "chain/ca-chain.crt").read_bytes()
    result["directories"] = tuple(
        mode(service / relative)
        for relative in (".", "private", "csr", "certs", "chain")
    )
    return result


def test_managed_issue_writer_publishes_and_cleans_exact_transaction(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
) -> None:
    toolset = tools()
    value = workspace(tmp_path / "case")
    env = environment(tmp_path / "environment")
    ready_ca(process_runner, value, env, toolset, INVENTORY)
    evidence = tmp_path / "openssl-ca-argv"
    wrapper = tmp_path / "openssl"
    wrapper.write_text(
        """#!/usr/bin/env bash
set -euo pipefail
if [[ ${1:-} == ca ]]; then
  printf '%s\n' "$@" >"$OPENSSL_FD_EVIDENCE"
fi
exec "$REAL_OPENSSL" "$@"
"""
    )
    wrapper.chmod(0o700)

    result = run(
        process_runner,
        _python_issue(value, "app"),
        dict(
            env,
            PATH=f"{wrapper.parent}:{env['PATH']}",
            REAL_OPENSSL=shutil.which("openssl", path=env["PATH"]) or "",
            OPENSSL_FD_EVIDENCE=os.fspath(evidence),
        ),
    )
    require_success(result, "Python managed service issuance")

    service = value.pki / "services/app"
    assert "[OK] Verified service certificate: app" in result.stdout
    assert "[OK] Issued service certificate:" in result.stdout
    assert_passphrase_content_absent(result, (value.intermediate_pass,))
    paths = (
        service / "private/tls.key",
        service / "csr/tls.csr",
        service / "certs/tls.crt",
        service / "chain/ca-chain.crt",
        service / "chain/fullchain.crt",
        service / "openssl.cnf",
        service / "issuer",
    )
    assert all(path.is_file() for path in paths)
    assert tuple(mode(path) for path in paths) == (
        0o600,
        0o600,
        0o644,
        0o644,
        0o644,
        0o600,
        0o600,
    )
    assert not (value.pki / "state/service/recovery-journal").exists()
    transactions = tuple((value.pki / "state/service/transactions").iterdir())
    assert len(transactions) == 1
    assert (transactions[0] / "transaction").is_file()
    assert (transactions[0] / "terminal").is_file()
    assert not (transactions[0] / "stage").exists()
    assert not (transactions[0] / "backup").exists()
    assert not tuple(Path(env["TMPDIR"]).glob(".platform-pki-service-*"))
    retained = (transactions[0] / "transaction").read_bytes()
    assert len(retained.splitlines()) == 13
    arguments = evidence.read_text().splitlines()
    assert "-passin" in arguments
    passin = arguments[arguments.index("-passin") + 1]
    assert re.fullmatch(r"fd:(?:[3-9]|[1-9][0-9]+)", passin)
    assert os.fspath(value.intermediate_pass) not in arguments
    assert not any(argument.startswith("file:") for argument in arguments)


def test_key_reuse_rotation_and_days_precedence(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
) -> None:
    toolset = tools()
    value = workspace(tmp_path / "case")
    env = environment(tmp_path / "environment")
    ready_ca(process_runner, value, env, toolset, INVENTORY)

    for service in ("reuse", "rotate"):
        key = value.pki / f"services/{service}/private/tls.key"
        key.parent.mkdir(mode=0o700, parents=True)
        key.parents[1].chmod(0o700)
        generated = openssl(
            process_runner,
            [
                "genpkey",
                "-algorithm",
                "EC",
                "-pkeyopt",
                "ec_paramgen_curve:secp384r1",
                "-out",
                key,
            ],
            env,
        )
        require_success(generated, f"{service} key fixture")
        key.chmod(0o600)

    reuse_key = value.pki / "services/reuse/private/tls.key"
    reuse_digest = digest(reuse_key)
    reused = run(
        process_runner,
        _python_issue(value, "reuse"),
        dict(env, PLATFORM_PKI_SERVICE_DAYS="32"),
    )
    require_success(reused, "managed key reuse")
    assert digest(reuse_key) == reuse_digest
    assert "[INFO] Reusing existing service private key:" in reused.stdout
    reuse_certificate = value.pki / "services/reuse/certs/tls.crt"
    assert openssl(
        process_runner,
        ["x509", "-in", reuse_certificate, "-checkend", str(31 * 86400), "-noout"],
        env,
    ).status == 0
    assert openssl(
        process_runner,
        ["x509", "-in", reuse_certificate, "-checkend", str(33 * 86400), "-noout"],
        env,
    ).status != 0

    rotate_key = value.pki / "services/rotate/private/tls.key"
    rotate_digest = digest(rotate_key)
    rotated = run(
        process_runner,
        _python_issue(value, "rotate", "--rotate-key", "--days", "31"),
        dict(env, PLATFORM_PKI_SERVICE_DAYS="40"),
    )
    require_success(rotated, "managed key rotation")
    assert digest(rotate_key) != rotate_digest
    archives = tuple((value.pki / "services/rotate/archive").glob("*/tls.key"))
    assert len(archives) == 1
    assert digest(archives[0]) == rotate_digest
    assert "[WARN] Archived previous service private key:" in rotated.stdout

    inventory_days = run(
        process_runner,
        _python_issue(value, "app"),
        dict(env, PLATFORM_PKI_SERVICE_DAYS="40"),
    )
    require_success(inventory_days, "inventory days precedence")
    app_certificate = value.pki / "services/app/certs/tls.crt"
    assert openssl(
        process_runner,
        ["x509", "-in", app_certificate, "-checkend", str(34 * 86400), "-noout"],
        env,
    ).status == 0
    assert openssl(
        process_runner,
        ["x509", "-in", app_certificate, "-checkend", str(36 * 86400), "-noout"],
        env,
    ).status != 0

    default_days = run(process_runner, _python_issue(value, "default"), env)
    require_success(default_days, "default days issuance")
    assert openssl(
        process_runner,
        [
            "x509",
            "-in",
            value.pki / "services/default/certs/tls.crt",
            "-checkend",
            str(396 * 86400),
            "-noout",
        ],
        env,
    ).status == 0


def test_bash_python_success_differential_has_narrow_dynamic_normalization(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
) -> None:
    toolset = tools()
    seed = workspace(tmp_path / "seed")
    seed_env = environment(tmp_path / "seed-environment")
    ready_ca(process_runner, seed, seed_env, toolset, INVENTORY)
    bash = _clone_workspace(seed, tmp_path / "bash")
    python = _clone_workspace(seed, tmp_path / "python")
    bash_env = environment(tmp_path / "bash-environment")
    python_env = environment(tmp_path / "python-environment")

    bash_result = run(
        process_runner,
        [
            toolset.issue,
            "app",
            "--namespace",
            bash.namespace,
            "--intermediate-pass-file",
            bash.intermediate_pass,
        ],
        bash_env,
    )
    python_result = run(process_runner, _python_issue(python, "app"), python_env)
    require_success(bash_result, "Bash differential issuance")
    require_success(python_result, "Python differential issuance")

    assert _semantic_state(python) == _semantic_state(bash)
    assert python_result.stdout.replace(os.fspath(python.pki), "<PKI>") == (
        bash_result.stdout.replace(os.fspath(bash.pki), "<PKI>")
    )
    assert _normalize_signing_stderr(python, python_result.stderr) == (
        _normalize_signing_stderr(bash, bash_result.stderr)
    )
    for value, env in ((bash, bash_env), (python, python_env)):
        certificate = value.pki / "services/app/certs/tls.crt"
        inspected = openssl(
            process_runner,
            [
                "x509",
                "-in",
                certificate,
                "-noout",
                "-subject",
                "-text",
            ],
            env,
        )
        require_success(inspected, "differential certificate inspection")
        assert "CN=app.example.internal" in inspected.stdout
        assert "DNS:app.example.internal" in inspected.stdout
        assert "IP Address:192.0.2.10" in inspected.stdout


def test_bash_python_invalid_differential_preserves_diagnostic_and_state(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
) -> None:
    toolset = tools()
    seed = workspace(tmp_path / "seed")
    seed_env = environment(tmp_path / "seed-environment")
    ready_ca(process_runner, seed, seed_env, toolset, INVENTORY)
    cases = (
        (
            "host-local",
            "Host-local service issuance requires authenticated CSR inputs: external",
        ),
        (
            "serial-collision",
            "Intermediate CA issued-certificate destination already exists",
        ),
        ("hostile-config", "must not contain include directives"),
        (
            "unsafe-mode",
            "Intermediate CA new-certificates directory is group- or world-writable",
        ),
    )

    for case, diagnostic in cases:
        bash = _clone_workspace(seed, tmp_path / f"bash-{case}")
        python = _clone_workspace(seed, tmp_path / f"python-{case}")
        bash_env = environment(tmp_path / f"bash-environment-{case}")
        python_env = environment(tmp_path / f"python-environment-{case}")
        service = "external" if case == "host-local" else "app"
        for value in (bash, python):
            authority = value.pki / "authorities/intermediates/g1-i1"
            if case == "serial-collision":
                (authority / "serial").write_text("00ab\n")
                (authority / "serial").chmod(0o600)
                collision = authority / "newcerts/AB.pem"
                collision.write_text("sentinel\n")
                collision.chmod(0o600)
            elif case == "hostile-config":
                config = authority / "openssl.cnf"
                config.write_text(config.read_text() + ".include /tmp/hostile.cnf\n")
                config.chmod(0o600)
            elif case == "unsafe-mode":
                (authority / "newcerts").chmod(0o777)

        bash_result = run(
            process_runner,
            [
                toolset.issue,
                service,
                "--namespace",
                bash.namespace,
                "--intermediate-pass-file",
                bash.intermediate_pass,
            ],
            bash_env,
        )
        python_result = run(
            process_runner,
            _python_issue(python, service),
            python_env,
        )

        assert bash_result.status == python_result.status == 1, case
        assert diagnostic in bash_result.stderr, case
        assert diagnostic in python_result.stderr, case
        assert not (bash.pki / f"services/{service}/certs/tls.crt").exists()
        assert not (python.pki / f"services/{service}/certs/tls.crt").exists()
        if case == "hostile-config":
            _assert_failed_transaction_clean(python)
        else:
            assert not (python.pki / "state/service/recovery-journal").exists()


def test_hard_crash_windows_recover_exact_precommit_or_committed_state(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
) -> None:
    toolset = tools()
    seed = workspace(tmp_path / "seed")
    seed_env = environment(tmp_path / "seed-environment")
    ready_ca(process_runner, seed, seed_env, toolset, INVENTORY)
    scenarios = (
        ("planning-after-journal", "rolled-back", ""),
        (
            "staging-service_certificate-after-mutation",
            "retained",
            "Unrecorded managed service service_certificate stage is unsafe",
        ),
        (
            "backup-ca_index-after-mutation",
            "retained",
            "Managed service backup cleanup prefix changed",
        ),
        ("openssl-before-mutation", "rolled-back", ""),
        ("openssl-after-mutation", "rolled-back", ""),
        ("publish-service_certificate-after-publication", "rolled-back", ""),
        ("verification-before-mutation", "rolled-back", ""),
        ("verification-after-mutation", "rolled-back", ""),
        ("commit-after-mutation", "committed", ""),
    )

    for index, (checkpoint, outcome, diagnostic) in enumerate(scenarios):
        value = _clone_workspace(seed, tmp_path / f"crash-{index}")
        env = environment(tmp_path / f"crash-environment-{index}")
        original_ca = _ca_state(value)
        crashed = run(
            process_runner,
            _python_issue(value, "app"),
            dict(env, PLATFORM_PKI_SERVICE_ISSUE_CRASH_AT=checkpoint),
        )
        assert crashed.status == 128 + signal.SIGKILL, (checkpoint, crashed)
        journal = value.pki / "state/service/recovery-journal"
        assert journal.is_file(), checkpoint
        journal_data = journal.read_bytes()
        assert len(journal_data.splitlines()) == len(SERVICE_TRANSACTION_FIELDS) == 485
        parsed = parse_service_transaction(journal_data, pki_dir=value.pki)
        assert parsed["operation"] == "service-issue"
        assert parsed["key_action"] == "create"

        recovered = run(process_runner, _recover(value), env)
        if outcome == "retained":
            assert recovered.status == 1, (checkpoint, recovered)
            assert diagnostic in recovered.stderr
            assert (value.pki / "state/service/recovery-journal").is_file()
            assert not (value.pki / "services/app/certs/tls.crt").exists()
            assert _ca_state(value) == original_ca, checkpoint
            continue

        require_success(recovered, f"recovery after {checkpoint}")
        if outcome == "committed":
            assert (value.pki / "services/app/certs/tls.crt").is_file()
            assert not (value.pki / "state/service/recovery-journal").exists()
        else:
            _assert_failed_transaction_clean(value)
            assert _ca_state(value) == original_ca, checkpoint
        assert not tuple(Path(env["TMPDIR"]).glob(".platform-pki-service-*"))


@pytest.mark.parametrize(
    "checkpoint",
    (
        "bootstrap-stage-after-mutation",
        "bootstrap-write-after-mutation",
        "bootstrap-file-fsync-after-mutation",
        "bootstrap-publication-after-mutation",
        "bootstrap-stage-unlink-after-mutation",
        "bootstrap-tree-after-mutation",
        "bootstrap-stage-dir-after-mutation",
        "bootstrap-backup-dir-after-mutation",
        "bootstrap-inputs-dir-after-mutation",
        "bootstrap-record-cleanup-before-mutation",
        "bootstrap-record-cleanup-after-mutation",
    ),
)
def test_bootstrap_hard_crash_is_exactly_recoverable(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    checkpoint: str,
) -> None:
    toolset = tools()
    value = workspace(tmp_path / "case")
    env = environment(tmp_path / "environment")
    ready_ca(process_runner, value, env, toolset, INVENTORY)
    original_ca = _ca_state(value)

    crashed = run(
        process_runner,
        _python_issue(value, "app"),
        dict(env, PLATFORM_PKI_SERVICE_ISSUE_CRASH_AT=checkpoint),
    )
    assert crashed.status == 128 + signal.SIGKILL, crashed
    transaction = _bootstrap_transaction(value)

    recovered = run(process_runner, _recover_exact(value, transaction), env)
    require_success(recovered, f"bootstrap recovery after {checkpoint}")
    assert not (value.pki / "state/service/bootstrap").exists()
    assert not tuple(
        (value.pki / "state/service").glob(".service-*.bootstrap.publish")
    )
    assert not (value.pki / "state/service/recovery-journal").exists()
    assert _ca_state(value) == original_ca
    assert not (value.pki / "services/app").exists()


@pytest.mark.parametrize("process_signal", (signal.SIGHUP, signal.SIGINT, signal.SIGTERM))
def test_bootstrap_handled_signal_cleans_before_returning(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    process_signal: signal.Signals,
) -> None:
    toolset = tools()
    value = workspace(tmp_path / "case")
    env = environment(tmp_path / "environment")
    ready_ca(process_runner, value, env, toolset, INVENTORY)
    original_ca = _ca_state(value)

    result = run(
        process_runner,
        _python_issue(value, "app"),
        dict(
            env,
            PLATFORM_PKI_SERVICE_ISSUE_SIGNAL_AT="bootstrap-tree-after-mutation",
            PLATFORM_PKI_SERVICE_ISSUE_SIGNAL=str(process_signal.value),
        ),
    )

    assert result.status == 128 + process_signal.value, result
    assert not (value.pki / "state/service/bootstrap").exists()
    assert not tuple(
        (value.pki / "state/service").glob(".service-*.bootstrap.publish")
    )
    assert not tuple((value.pki / "state/service/transactions").iterdir())
    assert _ca_state(value) == original_ca
    assert not (value.pki / "services/app").exists()


@pytest.mark.parametrize(
    ("issue_checkpoint", "recovery_checkpoint"),
    (
        (
            "bootstrap-stage-after-mutation",
            "bootstrap-stage-abandon-after-mutation",
        ),
        (
            "bootstrap-stage-after-mutation",
            "bootstrap-stage-cleanup-after-mutation",
        ),
        (
            "bootstrap-publication-after-mutation",
            "bootstrap-stage-cleanup-after-mutation",
        ),
        (
            "bootstrap-inputs-dir-after-mutation",
            "bootstrap-tree-cleanup-before-mutation",
        ),
        (
            "bootstrap-inputs-dir-after-mutation",
            "bootstrap-tree-cleanup-after-mutation",
        ),
        (
            "bootstrap-inputs-dir-after-mutation",
            "bootstrap-record-cleanup-before-mutation",
        ),
        (
            "bootstrap-inputs-dir-after-mutation",
            "bootstrap-record-cleanup-after-mutation",
        ),
    ),
)
def test_bootstrap_recovery_hard_crash_is_retryable_from_immutable_history(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    issue_checkpoint: str,
    recovery_checkpoint: str,
) -> None:
    toolset = tools()
    value = workspace(tmp_path / "case")
    env = environment(tmp_path / "environment")
    ready_ca(process_runner, value, env, toolset, INVENTORY)
    original_ca = _ca_state(value)
    crashed_issue = run(
        process_runner,
        _python_issue(value, "app"),
        dict(env, PLATFORM_PKI_SERVICE_ISSUE_CRASH_AT=issue_checkpoint),
    )
    assert crashed_issue.status == 128 + signal.SIGKILL, crashed_issue
    transaction = _bootstrap_transaction(value)

    crashed_recovery = run(
        process_runner,
        _recover_exact(value, transaction),
        dict(env, PLATFORM_PKI_SERVICE_RECOVER_CRASH_AT=recovery_checkpoint),
    )
    assert crashed_recovery.status == 128 + signal.SIGKILL, crashed_recovery

    recovered = run(process_runner, _recover_exact(value, transaction), env)
    require_success(recovered, f"retry after {recovery_checkpoint}")
    repeated = run(process_runner, _recover_exact(value, transaction), env)
    require_success(repeated, f"repeated recovery after {recovery_checkpoint}")
    assert "already recovered" in repeated.stdout
    history = value.pki / f"state/service/bootstrap-history/{transaction}"
    assert history.is_file()
    assert mode(history) == 0o600
    assert not (value.pki / "state/service/bootstrap").exists()
    assert not (value.pki / f"state/service/transactions/{transaction}").exists()
    assert _ca_state(value) == original_ca


@pytest.mark.parametrize(
    ("existing_key", "rotate_key", "key_action", "archive_state"),
    (
        (False, False, "create", "none"),
        (True, False, "reuse", "none"),
        (True, True, "rotate", "issue-key"),
    ),
)
def test_issue_journal_has_exact_485_field_contract_for_each_key_action(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    existing_key: bool,
    rotate_key: bool,
    key_action: str,
    archive_state: str,
) -> None:
    toolset = tools()
    value = workspace(tmp_path / "case")
    env = environment(tmp_path / "environment")
    ready_ca(process_runner, value, env, toolset, INVENTORY)
    key = value.pki / "services/app/private/tls.key"
    if existing_key:
        key.parent.mkdir(mode=0o700, parents=True)
        key.parents[1].chmod(0o700)
        generated = openssl(
            process_runner,
            [
                "genpkey",
                "-algorithm",
                "EC",
                "-pkeyopt",
                "ec_paramgen_curve:secp384r1",
                "-out",
                key,
            ],
            env,
        )
        require_success(generated, f"{key_action} key fixture")
        key.chmod(0o600)

    command = _python_issue(value, "app")
    if rotate_key:
        command.append("--rotate-key")
    crashed = run(
        process_runner,
        command,
        dict(env, PLATFORM_PKI_SERVICE_ISSUE_CRASH_AT="planning-after-journal"),
    )
    assert crashed.status == 128 + signal.SIGKILL, crashed
    journal = value.pki / "state/service/recovery-journal"
    data = journal.read_bytes()
    assert tuple(
        line.split(b"=", 1)[0].decode("ascii") for line in data.splitlines()
    ) == SERVICE_TRANSACTION_FIELDS
    assert len(SERVICE_TRANSACTION_FIELDS) == 485
    record = parse_service_transaction(data, pki_dir=value.pki)
    assert record["operation"] == "service-issue"
    assert record["key_action"] == key_action
    assert record["archive_state"] == archive_state
    assert (record["current_key_identity"] == "absent") is (not existing_key)

    recovered = run(process_runner, _recover(value), env)
    require_success(recovered, f"{key_action} planning recovery")
    _assert_failed_transaction_clean(value)


def test_handled_failure_and_signal_roll_back_before_returning(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
) -> None:
    toolset = tools()
    seed = workspace(tmp_path / "seed")
    seed_env = environment(tmp_path / "seed-environment")
    ready_ca(process_runner, seed, seed_env, toolset, INVENTORY)
    cases = (
        (
            "PLATFORM_PKI_SERVICE_ISSUE_FAILURE_AT",
            "verification-after-mutation",
            1,
            {},
        ),
        (
            "PLATFORM_PKI_SERVICE_ISSUE_SIGNAL_AT",
            "verification-after-mutation",
            128 + signal.SIGHUP,
            {"PLATFORM_PKI_SERVICE_ISSUE_SIGNAL": str(signal.SIGHUP)},
        ),
        (
            "PLATFORM_PKI_SERVICE_ISSUE_SIGNAL_AT",
            "verification-after-mutation",
            128 + signal.SIGINT,
            {"PLATFORM_PKI_SERVICE_ISSUE_SIGNAL": str(signal.SIGINT)},
        ),
        (
            "PLATFORM_PKI_SERVICE_ISSUE_SIGNAL_AT",
            "verification-after-mutation",
            128 + signal.SIGTERM,
            {"PLATFORM_PKI_SERVICE_ISSUE_SIGNAL": str(signal.SIGTERM)},
        ),
        (
            "PLATFORM_PKI_SERVICE_ISSUE_FAILURE_AT",
            "journal-before-mutation",
            1,
            {},
        ),
    )
    for index, (variable, checkpoint, status, extra) in enumerate(cases):
        value = _clone_workspace(seed, tmp_path / f"case-{index}")
        env = environment(tmp_path / f"environment-{index}")
        original_ca = _ca_state(value)
        result = run(
            process_runner,
            _python_issue(value, "app"),
            dict(env, **{variable: checkpoint}, **extra),
        )

        assert result.status == status, result
        if checkpoint == "journal-before-mutation":
            assert not (value.pki / "state/service/recovery-journal").exists()
            assert not tuple((value.pki / "state/service/transactions").iterdir())
            assert not (value.pki / "services/app").exists()
        else:
            _assert_failed_transaction_clean(value)
        assert _ca_state(value) == original_ca
        assert_passphrase_content_absent(result, (value.intermediate_pass,))


def test_planned_inventory_identity_race_fails_closed_with_evidence_retained(
    tmp_path: Path,
    process_starter: Callable[..., ManagedProcess],
    process_runner: Callable[..., ProcessResult],
) -> None:
    toolset = tools()
    value = workspace(tmp_path / "case")
    env = environment(tmp_path / "environment")
    ready_ca(process_runner, value, env, toolset, INVENTORY)
    marker = tmp_path / "paused"
    release = tmp_path / "release"
    process = process_starter(
        _python_issue(value, "app"),
        env=dict(
            env,
            PLATFORM_PKI_SERVICE_ISSUE_PAUSE_AT=(
                "staging-signing_inventory-before-mutation"
            ),
            PLATFORM_PKI_SERVICE_ISSUE_PAUSE_MARKER=os.fspath(marker),
            PLATFORM_PKI_SERVICE_ISSUE_PAUSE_RELEASE=os.fspath(release),
        ),
        timeout=120,
    )
    deadline = time.monotonic() + 10
    while (
        not marker.exists()
        and process.observe().status is None
        and time.monotonic() < deadline
    ):
        time.sleep(0.02)
    assert marker.exists(), process.observe()
    inventory = value.pki / "inventory/services.yml"
    replacement = inventory.with_name(".services.yml.replacement")
    replacement.write_bytes(inventory.read_bytes())
    replacement.chmod(0o600)
    os.replace(replacement, inventory)
    release.touch(mode=0o600)

    result = process.wait()

    assert result.status == 1, result
    assert "planned source identity changed" in result.stderr
    journal = value.pki / "state/service/recovery-journal"
    assert journal.is_file()
    assert not (value.pki / "services/app/certs/tls.crt").exists()
    recovered = run(process_runner, _recover(value), env)
    assert recovered.status == 1, recovered
    assert journal.is_file()


def test_active_issuer_identity_race_rolls_back_before_publication(
    tmp_path: Path,
    process_starter: Callable[..., ManagedProcess],
    process_runner: Callable[..., ProcessResult],
) -> None:
    toolset = tools()
    value = workspace(tmp_path / "case")
    env = environment(tmp_path / "environment")
    ready_ca(process_runner, value, env, toolset, INVENTORY)
    marker = tmp_path / "paused"
    release = tmp_path / "release"
    process = process_starter(
        _python_issue(value, "app"),
        env=dict(
            env,
            PLATFORM_PKI_SERVICE_ISSUE_PAUSE_AT=(
                "staging-signing_inventory-before-mutation"
            ),
            PLATFORM_PKI_SERVICE_ISSUE_PAUSE_MARKER=os.fspath(marker),
            PLATFORM_PKI_SERVICE_ISSUE_PAUSE_RELEASE=os.fspath(release),
        ),
        timeout=120,
    )
    deadline = time.monotonic() + 10
    while (
        not marker.exists()
        and process.observe().status is None
        and time.monotonic() < deadline
    ):
        time.sleep(0.02)
    assert marker.exists(), process.observe()
    active = value.pki / "state/active-issuer"
    replacement = active.with_name("active-issuer.replacement")
    replacement.write_bytes(active.read_bytes())
    replacement.chmod(0o600)
    replacement.replace(active)
    release.write_text("continue\n")

    result = process.wait()

    assert result.status == 1, result
    assert "Active issuer record identity changed" in result.stderr
    _assert_failed_transaction_clean(value)


@pytest.mark.parametrize(
    "content",
    (
        "operation=intermediate-bootstrap\ncommitted=true\n",
        "operation=rollover-prepare\ncommitted=true\n",
        "not-a-record\n",
    ),
)
def test_issue_rejects_non_authoritative_rollover_history_before_transaction(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    content: str,
) -> None:
    toolset = tools()
    value = workspace(tmp_path / "case")
    env = environment(tmp_path / "environment")
    ready_ca(process_runner, value, env, toolset, INVENTORY)
    journal = value.pki / "state/rollover/journal"
    journal.write_text(content)
    journal.chmod(0o600)

    result = run(process_runner, _python_issue(value, "app"), env)

    assert result.status == 1, result
    assert "PKI recovery is required before this command can continue" in result.stderr
    assert not (value.pki / "state/service").exists()
    assert not (value.pki / "services/app").exists()


def test_unsafe_derived_openssl_path_is_rejected_before_transaction(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
) -> None:
    toolset = tools()
    seed = workspace(tmp_path / "seed")
    seed_env = environment(tmp_path / "seed-environment")
    ready_ca(process_runner, seed, seed_env, toolset, INVENTORY)
    value = _clone_workspace(seed, tmp_path / "unsafe$path")
    env = environment(tmp_path / "environment")

    result = run(process_runner, _python_issue(value, "app"), env)

    assert result.status == 1, result
    assert "must not contain OpenSSL variable expansion syntax" in result.stderr
    assert not (value.pki / "state/service").exists()
    assert not (value.pki / "services/app").exists()


@pytest.mark.parametrize(
    ("mutation", "diagnostic"),
    (
        ("signature", "signature algorithm is not ECDSA with SHA-384"),
        ("serial", "serial does not match the planned CA serial"),
        ("basic-critical", "basic constraints profile is invalid"),
        ("extra-san", "DNS SAN set does not match inventory"),
    ),
)
def test_invalid_certificate_profile_output_rolls_back(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    mutation: str,
    diagnostic: str,
) -> None:
    toolset = tools()
    value = workspace(tmp_path / "case")
    env = environment(tmp_path / "environment")
    ready_ca(process_runner, value, env, toolset, INVENTORY)
    original_ca = _ca_state(value)
    wrapper = tmp_path / "openssl"
    wrapper.write_text(
        """#!/usr/bin/env bash
set -euo pipefail
arguments=" $* "
if [[ $PROFILE_MUTATION == signature && ${1:-} == x509 && $arguments == *' -text '* ]]; then
  "$REAL_OPENSSL" "$@" | sed 's/ecdsa-with-SHA384/sha256WithRSAEncryption/g'
  exit
fi
if [[ $PROFILE_MUTATION == serial && ${1:-} == x509 && $arguments == *' -serial '* ]]; then
  "$REAL_OPENSSL" "$@" | sed 's/^serial=.*/serial=DEAD/'
  exit
fi
if [[ $PROFILE_MUTATION == basic-critical && ${1:-} == x509 && $arguments == *' -ext basicConstraints '* ]]; then
  "$REAL_OPENSSL" "$@" | sed 's/: critical$/:/'
  exit
fi
if [[ $PROFILE_MUTATION == extra-san && ${1:-} == x509 && $arguments == *' -ext subjectAltName '* ]]; then
  "$REAL_OPENSSL" "$@" | sed '/DNS:/ s/$/, DNS:extra.example.internal/'
  exit
fi
exec "$REAL_OPENSSL" "$@"
"""
    )
    wrapper.chmod(0o700)

    result = run(
        process_runner,
        _python_issue(value, "app"),
        dict(
            env,
            PATH=f"{wrapper.parent}:{env['PATH']}",
            REAL_OPENSSL=shutil.which("openssl", path=env["PATH"]) or "",
            PROFILE_MUTATION=mutation,
        ),
    )

    assert result.status == 1, result
    assert diagnostic in result.stderr
    _assert_failed_transaction_clean(value)
    assert _ca_state(value) == original_ca


def test_published_verification_failure_rolls_back_all_publication(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
) -> None:
    toolset = tools()
    value = workspace(tmp_path / "case")
    env = environment(tmp_path / "environment")
    ready_ca(process_runner, value, env, toolset, INVENTORY)
    original_ca = _ca_state(value)
    wrapper = tmp_path / "openssl"
    wrapper.write_text(
        """#!/usr/bin/env bash
set -euo pipefail
if [[ ${1:-} == verify ]] && printf '%s\n' "$@" | grep -Fxq -- -untrusted; then
  exit 42
fi
exec "$REAL_OPENSSL" "$@"
"""
    )
    wrapper.chmod(0o700)

    result = run(
        process_runner,
        _python_issue(value, "app"),
        dict(
            env,
            PATH=f"{wrapper.parent}:{env['PATH']}",
            REAL_OPENSSL=shutil.which("openssl", path=env["PATH"]) or "",
        ),
    )

    assert result.status == 42, result
    assert "OpenSSL published certificate chain verification failed" in result.stderr
    _assert_failed_transaction_clean(value)
    assert _ca_state(value) == original_ca
