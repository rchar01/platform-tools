from __future__ import annotations

import os
import re
import shutil
import signal
import sys
from collections.abc import Callable, Mapping
from pathlib import Path

import pytest

from ..harness import ProcessResult
from .create_test_support import (
    CreateWorkspace,
    digest,
    environment,
    mode,
    ready_ca,
    require_success,
    run,
    tools,
    workspace,
)
from src.platform_pki.service_transaction import (
    ServiceOperation,
    parse_service_retained_transaction,
    parse_service_transaction,
)


pytestmark = pytest.mark.pki
REPOSITORY = Path(__file__).resolve().parents[2]
ISSUE_DRIVER = REPOSITORY / "tests/pki/service_issue_writer_driver.py"
RENEW_COMMAND = (REPOSITORY / "bin/platform-pki", "service-renew")
PUBLIC = REPOSITORY / "bin/platform-pki"
ORACLE_ROOT = REPOSITORY / "tests/pki/oracles/platform-pki-service-renew"
BASH_RENEW = ORACLE_ROOT / "platform-pki-service-renew"
ORACLE_LIB = ORACLE_ROOT / "lib"
INVENTORY = """services:
  app:
    common_name: app.example.internal
    dns:
      - app.example.internal
    ips:
      - 192.0.2.10
    days: 35
  rotate:
    common_name: rotate.example.internal
    dns:
      - rotate.example.internal
"""


def _command(
    command: Path | tuple[Path | str, ...],
    value: CreateWorkspace,
    service: str,
    *arguments: str,
) -> list[str | Path]:
    prefix: tuple[Path | str, ...]
    if isinstance(command, Path):
        prefix = (sys.executable, command)
    else:
        prefix = command
    return [
        *prefix,
        service,
        "--pki-dir",
        value.pki,
        "--intermediate-pass-file",
        value.intermediate_pass,
        *arguments,
    ]


def _operational_files(value: CreateWorkspace, service: str) -> dict[str, tuple[int, bytes]]:
    service_root = value.pki / "services" / service
    authority = value.pki / "authorities/intermediates/g1-i1"
    paths = (
        service_root / "private/tls.key",
        service_root / "csr/tls.csr",
        service_root / "certs/tls.crt",
        service_root / "chain/ca-chain.crt",
        service_root / "chain/fullchain.crt",
        service_root / "openssl.cnf",
        service_root / "issuer",
        authority / "index.txt",
        authority / "index.txt.attr",
        authority / "serial",
        authority / "index.txt.old",
        authority / "index.txt.attr.old",
        authority / "serial.old",
    )
    return {
        os.fspath(path.relative_to(value.pki)): (mode(path), path.read_bytes())
        for path in paths
        if path.is_file()
    }


def _renewal_public_state(value: CreateWorkspace, service: str) -> tuple[object, ...]:
    archive = value.pki / "services" / service / "archive"
    archive_state = (
        tuple(
            (
                os.fspath(path.relative_to(archive)),
                "directory" if path.is_dir() else "file",
                mode(path),
                None if path.is_dir() else digest(path),
            )
            for path in sorted(archive.rglob("*"))
            if path.name != ".platform-pki-renew-archive"
        )
        if archive.is_dir()
        else ()
    )
    newcerts = value.pki / "authorities/intermediates/g1-i1/newcerts"
    return (
        _operational_files(value, service),
        tuple(
            (path.name, mode(path), digest(path))
            for path in sorted(newcerts.iterdir())
        ),
        archive_state,
    )


def _ready(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
) -> tuple[CreateWorkspace, Mapping[str, str]]:
    value = workspace(tmp_path / "case")
    env = environment(tmp_path / "environment")
    ready_ca(process_runner, value, env, tools(), INVENTORY)
    for service in ("app", "rotate"):
        result = run(process_runner, _command(ISSUE_DRIVER, value, service), env)
        require_success(result, f"Python managed service issue for {service}")
    return value, env


def _clone(value: CreateWorkspace, root: Path) -> CreateWorkspace:
    shutil.copytree(value.root, root, copy_function=shutil.copy2)
    clone = CreateWorkspace(
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
        config = clone.pki / relative
        config.write_bytes(
            config.read_bytes().replace(
                os.fsencode(value.pki), os.fsencode(clone.pki)
            )
        )
        config.chmod(0o600)
    (clone.pki / "state/rollover/journal").unlink(missing_ok=True)
    return clone


def _semantic_renewal_state(value: CreateWorkspace) -> dict[str, object]:
    service = value.pki / "services/app"
    authority = value.pki / "authorities/intermediates/g1-i1"
    archive = tuple((service / "archive").iterdir())
    assert len(archive) == 1
    state: dict[str, object] = {
        "key": (
            mode(service / "private/tls.key"),
            digest(service / "private/tls.key"),
        ),
        "config": (
            mode(service / "openssl.cnf"),
            (service / "openssl.cnf").read_bytes(),
        ),
        "issuer": (mode(service / "issuer"), (service / "issuer").read_bytes()),
        "chain": (
            mode(service / "chain/ca-chain.crt"),
            (service / "chain/ca-chain.crt").read_bytes(),
        ),
        "modes": tuple(
            mode(service / relative)
            for relative in (
                "csr/tls.csr",
                "certs/tls.crt",
                "chain/fullchain.crt",
            )
        ),
        "archive": tuple(
            (path.name, mode(path), path.read_bytes())
            for path in sorted(archive[0].iterdir())
        ),
        "ca-static": tuple(
            (name, mode(authority / name), (authority / name).read_bytes())
            for name in (
                "index.txt.attr",
                "serial",
                "index.txt.old",
                "index.txt.attr.old",
                "serial.old",
            )
        ),
        "newcerts": tuple(
            (path.name, mode(path))
            for path in sorted((authority / "newcerts").iterdir())
        ),
        "newcert-equals-service": (
            (authority / "newcerts/1001.pem").read_bytes()
            == (service / "certs/tls.crt").read_bytes()
        ),
    }
    state["index"] = tuple(
        (fields[0], *fields[2:])
        for fields in (
            line.split("\t")
            for line in (authority / "index.txt").read_text().splitlines()
        )
    )
    return state


def _normalize_output(value: CreateWorkspace, content: str) -> str:
    normalized = content.replace(os.fspath(value.pki), "<PKI>")
    normalized = re.sub(
        r"<PKI>/services/app/archive/[0-9]{8}-[0-9]{6}(?:-[0-9]{2})?",
        "<PKI>/services/app/archive/<ARCHIVE>",
        normalized,
    )
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


def test_bash_python_managed_renewal_operational_state_is_equivalent(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
) -> None:
    seed, _seed_environment = _ready(tmp_path, process_runner)
    bash = _clone(seed, tmp_path / "bash")
    python = _clone(seed, tmp_path / "python")
    bash_environment = environment(tmp_path / "bash-environment")
    bash_environment["PLATFORM_TOOLS_LIB_DIR"] = os.fspath(ORACLE_LIB)
    python_environment = environment(tmp_path / "python-environment")

    bash_result = run(
        process_runner,
        [
            BASH_RENEW,
            "app",
            "--namespace",
            bash.namespace,
            "--intermediate-pass-file",
            bash.intermediate_pass,
        ],
        bash_environment,
    )
    python_result = run(
        process_runner,
        _command(RENEW_COMMAND, python, "app"),
        python_environment,
    )
    require_success(bash_result, "Bash managed service renewal")
    require_success(python_result, "Python managed service renewal")

    assert _semantic_renewal_state(python) == _semantic_renewal_state(bash)
    assert _normalize_output(python, python_result.stdout) == _normalize_output(
        bash, bash_result.stdout
    )
    assert _normalize_output(python, python_result.stderr) == _normalize_output(
        bash, bash_result.stderr
    )
    profiles = []
    for value, process_environment in (
        (bash, bash_environment),
        (python, python_environment),
    ):
        inspected = run(
            process_runner,
            [
                "openssl",
                "x509",
                "-in",
                value.pki / "services/app/certs/tls.crt",
                "-noout",
                "-subject",
                "-issuer",
                "-serial",
                "-ext",
                "subjectAltName",
            ],
            process_environment,
        )
        require_success(inspected, "renewal differential certificate inspection")
        profiles.append(inspected.stdout)
        assert not (value.pki / "state/service/recovery-journal").exists()
    assert profiles[0] == profiles[1]


def test_managed_renew_writer_archives_sparse_state_and_rotated_key(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
) -> None:
    value, env = _ready(tmp_path, process_runner)
    service = value.pki / "services/app"
    old_key = digest(service / "private/tls.key")
    old_certificate = digest(service / "certs/tls.crt")

    result = run(process_runner, _command(RENEW_COMMAND, value, "app"), env)
    require_success(result, "Python managed service renewal")
    assert "[OK] Renewed service certificate:" in result.stdout
    assert digest(service / "private/tls.key") == old_key
    assert digest(service / "certs/tls.crt") != old_certificate
    archive = next((service / "archive").iterdir())
    assert not (archive / ".platform-pki-renew-archive").exists()
    assert tuple(sorted(path.name for path in archive.iterdir())) == (
        "ca-chain.crt",
        "fullchain.crt",
        "issuer",
        "openssl.cnf",
        "tls.crt",
        "tls.csr",
    )

    rotate = value.pki / "services/rotate"
    for relative in (
        "certs/tls.crt",
        "csr/tls.csr",
        "chain/ca-chain.crt",
        "chain/fullchain.crt",
        "openssl.cnf",
    ):
        (rotate / relative).unlink()
    old_rotate_key = digest(rotate / "private/tls.key")
    result = run(
        process_runner,
        _command(RENEW_COMMAND, value, "rotate", "--rotate-key", "--days", "31"),
        env,
    )
    require_success(result, "Python managed sparse service renewal")
    assert digest(rotate / "private/tls.key") != old_rotate_key
    rotate_archive = next((rotate / "archive").iterdir())
    assert tuple(sorted(path.name for path in rotate_archive.iterdir())) == (
        "issuer",
        "tls.key",
    )
    assert digest(rotate_archive / "tls.key") == old_rotate_key

    retained = tuple(
        parse_service_retained_transaction(path.read_bytes())
        for path in (value.pki / "state/service/transactions").glob("*/transaction")
    )
    renewals = tuple(
        item for item in retained if item["operation"] == ServiceOperation.RENEW.value
    )
    assert len(renewals) == 2
    assert not (value.pki / "state/service/recovery-journal").exists()


def test_managed_renew_writer_failure_rolls_back_complete_operational_state(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
) -> None:
    value, env = _ready(tmp_path, process_runner)
    before = _operational_files(value, "app")
    result = run(
        process_runner,
        _command(RENEW_COMMAND, value, "app", "--rotate-key"),
        dict(env, PLATFORM_PKI_SERVICE_RENEW_FAILURE_AT="verification-after-mutation"),
    )
    assert result.status == 1
    assert "Injected operation failure" in result.stderr
    assert _operational_files(value, "app") == before
    assert not (value.pki / "services/app/archive").exists()
    assert not (value.pki / "state/service/recovery-journal").exists()
    retained = tuple(
        parse_service_retained_transaction(path.read_bytes())
        for path in (value.pki / "state/service/transactions").glob("*/transaction")
    )
    assert sum(
        item["operation"] == ServiceOperation.RENEW.value for item in retained
    ) == 1


def test_managed_renew_writer_hard_crash_uses_exact_public_recovery(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
) -> None:
    seed, _seed_environment = _ready(tmp_path, process_runner)
    for index, (checkpoint, committed) in enumerate(
        (
            ("verification-after-mutation", False),
            ("commit-after-mutation", True),
        )
    ):
        value = _clone(seed, tmp_path / f"recovery-{index}")
        process_environment = environment(tmp_path / f"recovery-environment-{index}")
        before = _renewal_public_state(value, "app")
        crashed = run(
            process_runner,
            _command(RENEW_COMMAND, value, "app", "--rotate-key"),
            dict(
                process_environment,
                PLATFORM_PKI_SERVICE_RENEW_CRASH_AT=checkpoint,
            ),
        )
        assert crashed.status == 128 + signal.SIGKILL, crashed
        journal = value.pki / "state/service/recovery-journal"
        record = parse_service_transaction(journal.read_bytes(), pki_dir=value.pki)
        transaction = record["transaction"]
        recovery_command = [
            PUBLIC,
            "service-recover",
            "--pki-dir",
            value.pki,
            "--transaction",
            transaction,
            "--yes",
        ]
        crashed_public_state = _renewal_public_state(value, "app")
        crashed_state = (
            crashed_public_state,
            mode(journal),
            digest(journal),
        )

        interrupted = run(
            process_runner,
            recovery_command,
            dict(
                process_environment,
                PLATFORM_PKI_SERVICE_RECOVER_FAILURE_AT="journal-loaded",
            ),
        )
        assert interrupted.status == 1
        assert interrupted.stdout == ""
        assert interrupted.stderr == "[ERROR] Injected operation failure\n"
        assert (
            _renewal_public_state(value, "app"),
            mode(journal),
            digest(journal),
        ) == crashed_state

        recovered = run(
            process_runner,
            recovery_command,
            process_environment,
        )
        outcome = "succeeded" if committed else "failed-pre-commit"
        assert recovered.status == 0
        assert recovered.stdout == (
            f"[OK] Recovered managed service transaction: app ({outcome})\n"
        )
        assert recovered.stderr == ""
        assert not journal.exists()
        retained = value.pki / f"state/service/transactions/{transaction}"
        assert (retained / "terminal").is_file()
        assert not (retained / "stage").exists()
        assert not (retained / "backup").exists()
        if committed:
            archive = next((value.pki / "services/app/archive").iterdir())
            assert not (archive / ".platform-pki-renew-archive").exists()
            assert _renewal_public_state(value, "app") == crashed_public_state
        else:
            assert not (value.pki / "services/app/archive").exists()
            assert _renewal_public_state(value, "app") == before
