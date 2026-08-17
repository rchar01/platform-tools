from __future__ import annotations

import os
import signal
import sys
import time
from collections.abc import Callable, Mapping
from pathlib import Path

import pytest

from src.platform_pki.csr_recover import CSR_FINALIZATION_RECOVERY_CHECKPOINTS

from ..harness import ProcessResult
from .migration_harness import (
    copy_private_case,
    managed_openssl_dir_normalizer,
    snapshot_state,
)
from .support import assert_result, digest, environment, write_private
from .test_csr_candidate import (
    CANDIDATE,
    REQUEST_ID,
    decide,
    prepare,
    publish_request,
    write_evidence,
)
from .test_csr_signing import CsrWorkspace, RENEW, csr_workspace, write_exchange


pytestmark = pytest.mark.pki

REPOSITORY = Path(__file__).resolve().parents[2]
DRIVER = REPOSITORY / "tests/pki/csr_finalization_recover_driver.py"
ORACLE_ROOT = REPOSITORY / "tests/pki/oracles/platform-pki-csr-recover"
BASH_RECOVER = ORACLE_ROOT / "platform-pki-csr-recover"
ORACLE_LIB = ORACLE_ROOT / "lib"
RENEWAL_ID = "2123456789abcdef0123456789abcdef"


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


def _prepare_finalization(
    workspace: CsrWorkspace,
    mode: str,
) -> tuple[str, Path, str, Path, Path]:
    artifact, manifest = prepare(workspace)
    request_id = REQUEST_ID
    if mode == "exchange":
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
        current = artifact / "tls.crt"
        write_exchange(
            workspace,
            "renew",
            RENEWAL_ID,
            "cd" * 32,
            digest(current),
        )
        assert_result(workspace.sign(RENEW, current_cert=current), 0)
        artifact, manifest = publish_request(workspace, RENEWAL_ID)
        request_id = RENEWAL_ID
    evidence, signature = write_evidence(
        workspace,
        artifact,
        action="finalize",
        result="activated",
        request_id=request_id,
    )
    return request_id, artifact, manifest, evidence, signature


def _crash_finalization(
    workspace: CsrWorkspace,
    prepared: tuple[str, Path, str, Path, Path],
    checkpoint: str,
) -> None:
    request_id, _artifact, manifest, evidence, signature = prepared
    result = workspace.runner(
        [
            *CANDIDATE,
            "finalize",
            "external",
            "--request-id",
            request_id,
            "--artifact-manifest-sha256",
            manifest,
            "--evidence-file",
            evidence,
            "--evidence-signature",
            signature,
            "--yes",
            "--namespace",
            workspace.namespace,
        ],
        env=environment(
            workspace.env,
            PLATFORM_PKI_CANDIDATE_CRASH_AT=checkpoint,
        ),
        timeout=120,
    )
    assert result.status == 128 + signal.SIGKILL, result


def _python_recover(
    workspace: CsrWorkspace,
    *,
    env: Mapping[str, str] | None = None,
) -> ProcessResult:
    return workspace.runner(
        [
            sys.executable,
            DRIVER,
            "--pki-dir",
            workspace.pki,
        ],
        env=workspace.env if env is None else env,
        timeout=120,
    )


@pytest.mark.parametrize("mode", ("create", "exchange"))
@pytest.mark.parametrize(
    "checkpoint", ("journal-written", "outcome-published", "active-published")
)
def test_python_recovers_every_final_bash_finalization_phase(
    csr_workspace: CsrWorkspace,
    mode: str,
    checkpoint: str,
) -> None:
    prepared = _prepare_finalization(csr_workspace, mode)
    _crash_finalization(csr_workspace, prepared, checkpoint)
    request_id = prepared[0]

    result = _python_recover(csr_workspace)

    assert_result(
        result,
        0,
        stdout=(
            "[OK] Recovered CSR candidate finalization: "
            f"external/{request_id}\n"
        ),
        stderr="",
    )
    assert not (csr_workspace.pki / "state/csr/finalization-recovery-journal").exists()
    assert (
        csr_workspace.pki / f"state/csr/outcomes/external/{request_id}"
    ).is_dir()
    active = dict(
        line.split("=", 1)
        for line in (csr_workspace.pki / "state/csr/active/external")
        .read_text(encoding="ascii")
        .splitlines()
    )
    assert active["request_id"] == request_id
    assert not tuple((csr_workspace.pki / "state/csr/active").glob(".platform-pki-*"))


def _prepare_checkpoint_state(
    workspace: CsrWorkspace,
    point: str,
) -> tuple[str, str]:
    mode = "exchange" if point.startswith("old-active-") else "create"
    prepared = _prepare_finalization(workspace, mode)
    _crash_finalization(workspace, prepared, "journal-written")
    return mode, prepared[0]


@pytest.mark.parametrize(
    "point",
    CSR_FINALIZATION_RECOVERY_CHECKPOINTS,
    ids=CSR_FINALIZATION_RECOVERY_CHECKPOINTS,
)
def test_python_recovery_restarts_after_every_recovery_checkpoint(
    csr_workspace: CsrWorkspace,
    point: str,
) -> None:
    _mode, request_id = _prepare_checkpoint_state(csr_workspace, point)
    crashed = _python_recover(
        csr_workspace,
        env=environment(
            csr_workspace.env,
            PLATFORM_PKI_CSR_RECOVER_CRASH_AT=point,
        ),
    )
    assert crashed.status == 128 + signal.SIGKILL, crashed
    journal = csr_workspace.pki / "state/csr/finalization-recovery-journal"
    assert journal.is_file()

    recovered = _python_recover(csr_workspace)

    assert_result(recovered, 0, stderr="")
    assert not journal.exists()
    assert (
        csr_workspace.pki / f"state/csr/outcomes/external/{request_id}"
    ).is_dir()


@pytest.mark.parametrize("mode", ("create", "exchange"))
@pytest.mark.parametrize("point", ("outcome-after-mutation", "active-after-mutation"))
def test_mutation_before_journal_windows_resume_in_both_active_modes(
    csr_workspace: CsrWorkspace,
    mode: str,
    point: str,
) -> None:
    prepared = _prepare_finalization(csr_workspace, mode)
    _crash_finalization(csr_workspace, prepared, "journal-written")
    crashed = _python_recover(
        csr_workspace,
        env=environment(
            csr_workspace.env,
            PLATFORM_PKI_CSR_RECOVER_CRASH_AT=point,
        ),
    )
    assert crashed.status == 128 + signal.SIGKILL, crashed

    recovered = _python_recover(csr_workspace)

    assert_result(recovered, 0, stderr="")
    assert not (
        csr_workspace.pki / "state/csr/finalization-recovery-journal"
    ).exists()


def _replace_file(path: Path, content: bytes | None = None) -> None:
    replacement = path.with_name(f".{path.name}.replacement")
    replacement.write_bytes(path.read_bytes() if content is None else content)
    replacement.chmod(0o600)
    os.replace(replacement, path)


@pytest.mark.parametrize(
    "kind",
    (
        "source-replacement",
        "source-digest",
        "candidate-directory",
        "response-directory",
        "artifact-directory",
        "transaction-directory",
        "trust-replacement",
        "trust-digest",
        "outcome-replacement",
        "outcome-digest",
        "active-replacement",
        "active-digest",
        "outcome-both-present",
        "outcome-both-absent",
        "active-both-present",
        "active-both-absent",
    ),
)
def test_python_recovery_rejects_replaced_ambiguous_or_changed_state(
    csr_workspace: CsrWorkspace,
    kind: str,
) -> None:
    prepared = _prepare_finalization(csr_workspace, "create")
    _crash_finalization(csr_workspace, prepared, "journal-written")
    journal = csr_workspace.pki / "state/csr/finalization-recovery-journal"
    values = dict(line.split("=", 1) for line in journal.read_text().splitlines())

    if kind == "source-replacement":
        _replace_file(Path(values["response_path"]))
    elif kind == "source-digest":
        text = journal.read_text(encoding="ascii")
        for field in ("response_sha256", "source_response_response_sha256"):
            text = text.replace(f"{field}={values[field]}", f"{field}={'f' * 64}")
        write_private(journal, text)
    elif kind.endswith("-directory"):
        field = {
            "candidate-directory": "candidate_dir",
            "response-directory": "response_dir",
            "artifact-directory": "artifact_dir",
            "transaction-directory": "transaction_dir",
        }[kind]
        directory = Path(values[field])
        directory.rename(directory.with_name(f".{directory.name}.displaced"))
        directory.mkdir(mode=0o700)
    elif kind == "trust-replacement":
        _replace_file(Path(values["response_trust_path"]))
    elif kind == "trust-digest":
        text = journal.read_text(encoding="ascii")
        text = text.replace(
            f"response_trust_sha256={values['response_trust_sha256']}",
            f"response_trust_sha256={'f' * 64}",
        )
        write_private(journal, text)
    elif kind == "outcome-replacement":
        _replace_file(Path(values["outcome_stage"]) / "decision")
    elif kind == "outcome-digest":
        text = journal.read_text(encoding="ascii")
        text = text.replace(
            f"decision_sha256={values['decision_sha256']}",
            f"decision_sha256={'f' * 64}",
        )
        write_private(journal, text)
    elif kind == "active-replacement":
        _replace_file(Path(values["active_stage"]))
    elif kind == "active-digest":
        text = journal.read_text(encoding="ascii")
        text = text.replace(
            f"active_sha256={values['active_sha256']}",
            f"active_sha256={'f' * 64}",
        )
        write_private(journal, text)
    elif kind == "outcome-both-present":
        destination = Path(values["outcome_destination"])
        destination.mkdir(mode=0o700)
    elif kind == "outcome-both-absent":
        Path(values["outcome_stage"]).rename(
            Path(values["outcome_stage"]).with_name("detached-outcome")
        )
    elif kind == "active-both-present":
        destination = Path(values["active_destination"])
        destination.write_bytes(Path(values["active_stage"]).read_bytes())
        destination.chmod(0o600)
    else:
        Path(values["active_stage"]).rename(
            Path(values["active_stage"]).with_name("detached-active")
        )

    before = snapshot_state(csr_workspace.pki)
    result = _python_recover(csr_workspace)

    assert result.status == 1, (kind, result)
    assert result.stdout == ""
    assert snapshot_state(csr_workspace.pki) == before
    assert journal.is_file()


@pytest.mark.parametrize("kind", ("mode", "hardlink", "symlink", "oversize"))
def test_finalization_journal_requires_bounded_private_no_follow_access(
    csr_workspace: CsrWorkspace,
    kind: str,
) -> None:
    prepared = _prepare_finalization(csr_workspace, "create")
    _crash_finalization(csr_workspace, prepared, "journal-written")
    journal = csr_workspace.pki / "state/csr/finalization-recovery-journal"
    if kind == "mode":
        journal.chmod(0o640)
    elif kind == "hardlink":
        os.link(journal, journal.with_name("journal-hardlink"))
    elif kind == "symlink":
        retained = journal.with_name("journal-retained")
        journal.rename(retained)
        journal.symlink_to(retained.name)
    else:
        with journal.open("ab") as stream:
            stream.write(b"x" * (1024 * 1024))

    before = snapshot_state(csr_workspace.pki)
    result = _python_recover(csr_workspace)

    assert result.status == 1, (kind, result)
    assert result.stdout == ""
    assert snapshot_state(csr_workspace.pki) == before


@pytest.mark.parametrize("kind", ("signing", "rollover"))
def test_finalization_recovery_rejects_incompatible_unresolved_state(
    csr_workspace: CsrWorkspace,
    kind: str,
) -> None:
    prepared = _prepare_finalization(csr_workspace, "create")
    _crash_finalization(csr_workspace, prepared, "journal-written")
    if kind == "signing":
        incompatible = csr_workspace.pki / "state/csr/recovery-journal"
    else:
        incompatible = csr_workspace.pki / "state/rollover/recovery-required"
    write_private(incompatible, "operation=unresolved\n")
    before = snapshot_state(csr_workspace.pki)

    result = _python_recover(csr_workspace)

    assert result.status == 1, result
    assert result.stdout == ""
    assert snapshot_state(csr_workspace.pki) == before


def test_finalization_recovery_rejects_transaction_mismatch(
    csr_workspace: CsrWorkspace,
) -> None:
    prepared = _prepare_finalization(csr_workspace, "create")
    _crash_finalization(csr_workspace, prepared, "journal-written")
    before = snapshot_state(csr_workspace.pki)

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

    assert result.status == 1, result
    assert "does not match" in result.stderr
    assert snapshot_state(csr_workspace.pki) == before


def _wait_for_path(path: Path, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    while not path.exists():
        if time.monotonic() >= deadline:
            pytest.fail(f"timed out waiting for pause marker: {path}", pytrace=False)
        time.sleep(0.01)


def test_journal_replacement_after_load_is_preserved(
    csr_workspace: CsrWorkspace,
    process_starter,
) -> None:
    prepared = _prepare_finalization(csr_workspace, "create")
    _crash_finalization(csr_workspace, prepared, "journal-written")
    journal = csr_workspace.pki / "state/csr/finalization-recovery-journal"
    marker = csr_workspace.artifacts / "recover-pause"
    release = csr_workspace.artifacts / "recover-release"
    process = process_starter(
        [sys.executable, DRIVER, "--pki-dir", csr_workspace.pki],
        env=environment(
            csr_workspace.env,
            PLATFORM_PKI_CSR_RECOVER_PAUSE_AT="journal-written",
            PLATFORM_PKI_CSR_RECOVER_PAUSE_MARKER=os.fspath(marker),
            PLATFORM_PKI_CSR_RECOVER_PAUSE_RELEASE=os.fspath(release),
        ),
        timeout=120,
    )
    with process:
        _wait_for_path(marker)
        replacement = journal.read_bytes()
        _replace_file(journal, replacement)
        release.touch(mode=0o600)
        result = process.wait()
    assert result.status == 1, result
    assert journal.read_bytes() == replacement
    assert not Path(
        dict(line.split("=", 1) for line in replacement.decode().splitlines())[
            "outcome_destination"
        ]
    ).exists()
    assert not (
        csr_workspace.pki / "state/csr/active/external"
    ).exists()


def test_old_pointer_cleanup_replacement_is_preserved(
    csr_workspace: CsrWorkspace,
    process_starter,
) -> None:
    prepared = _prepare_finalization(csr_workspace, "exchange")
    _crash_finalization(csr_workspace, prepared, "journal-written")
    marker = csr_workspace.artifacts / "cleanup-pause"
    release = csr_workspace.artifacts / "cleanup-release"
    process = process_starter(
        [sys.executable, DRIVER, "--pki-dir", csr_workspace.pki],
        env=environment(
            csr_workspace.env,
            PLATFORM_PKI_CSR_RECOVER_PAUSE_AT="old-active-before-cleanup",
            PLATFORM_PKI_CSR_RECOVER_PAUSE_MARKER=os.fspath(marker),
            PLATFORM_PKI_CSR_RECOVER_PAUSE_RELEASE=os.fspath(release),
        ),
        timeout=120,
    )
    with process:
        _wait_for_path(marker)
        journal = csr_workspace.pki / "state/csr/finalization-recovery-journal"
        values = dict(line.split("=", 1) for line in journal.read_text().splitlines())
        stage = Path(values["active_stage"])
        _replace_file(stage, b"hostile replacement\n")
        hostile = stage.stat()
        release.touch(mode=0o600)
        result = process.wait()
    assert result.status == 1, result
    assert stage.stat().st_ino == hostile.st_ino
    assert stage.read_bytes() == b"hostile replacement\n"
    assert journal.is_file()


@pytest.mark.parametrize(
    "checkpoint,path_field",
    (
        ("outcome-before-mutation", "outcome_destination"),
        ("active-before-mutation", "active_destination"),
    ),
)
def test_publication_parent_replacement_fails_before_mutation(
    csr_workspace: CsrWorkspace,
    process_starter,
    checkpoint: str,
    path_field: str,
) -> None:
    prepared = _prepare_finalization(csr_workspace, "create")
    _crash_finalization(csr_workspace, prepared, "journal-written")
    journal = csr_workspace.pki / "state/csr/finalization-recovery-journal"
    marker = csr_workspace.artifacts / f"{checkpoint}-pause"
    release = csr_workspace.artifacts / f"{checkpoint}-release"
    process = process_starter(
        [sys.executable, DRIVER, "--pki-dir", csr_workspace.pki],
        env=environment(
            csr_workspace.env,
            PLATFORM_PKI_CSR_RECOVER_PAUSE_AT=checkpoint,
            PLATFORM_PKI_CSR_RECOVER_PAUSE_MARKER=os.fspath(marker),
            PLATFORM_PKI_CSR_RECOVER_PAUSE_RELEASE=os.fspath(release),
        ),
        timeout=120,
    )
    with process:
        _wait_for_path(marker)
        values = dict(line.split("=", 1) for line in journal.read_text().splitlines())
        destination = Path(values[path_field])
        parent = destination.parent
        displaced = parent.with_name(f"{parent.name}.displaced")
        os.rename(parent, displaced)
        parent.mkdir(mode=0o700)
        release.touch(mode=0o600)
        result = process.wait()
    assert result.status == 1, result
    assert not tuple(parent.iterdir())
    stage_field = path_field.replace("destination", "stage")
    assert (displaced / Path(values[stage_field]).name).exists()
    assert not (displaced / destination.name).exists()
    assert journal.is_file()


def test_journal_cleanup_replacement_is_preserved(
    csr_workspace: CsrWorkspace,
    process_starter,
) -> None:
    prepared = _prepare_finalization(csr_workspace, "create")
    _crash_finalization(csr_workspace, prepared, "journal-written")
    journal = csr_workspace.pki / "state/csr/finalization-recovery-journal"
    marker = csr_workspace.artifacts / "journal-cleanup-pause"
    release = csr_workspace.artifacts / "journal-cleanup-release"
    process = process_starter(
        [sys.executable, DRIVER, "--pki-dir", csr_workspace.pki],
        env=environment(
            csr_workspace.env,
            PLATFORM_PKI_CSR_RECOVER_PAUSE_AT="journal-before-cleanup",
            PLATFORM_PKI_CSR_RECOVER_PAUSE_MARKER=os.fspath(marker),
            PLATFORM_PKI_CSR_RECOVER_PAUSE_RELEASE=os.fspath(release),
        ),
        timeout=120,
    )
    with process:
        _wait_for_path(marker)
        replacement = journal.read_bytes()
        _replace_file(journal, replacement)
        replaced_inode = journal.stat().st_ino
        release.touch(mode=0o600)
        result = process.wait()
    assert result.status == 1, result
    assert journal.stat().st_ino == replaced_inode
    assert journal.read_bytes() == replacement
    values = dict(line.split("=", 1) for line in replacement.decode().splitlines())
    assert Path(values["outcome_destination"]).is_dir()
    assert Path(values["active_destination"]).is_file()


@pytest.mark.parametrize("mode", ("create", "exchange"))
@pytest.mark.parametrize(
    "checkpoint", ("journal-written", "outcome-published", "active-published")
)
def test_final_bash_and_python_recovery_have_equivalent_terminal_state(
    tmp_path: Path,
    csr_workspace: CsrWorkspace,
    process_runner: Callable[..., ProcessResult],
    isolated_environment: Mapping[str, str],
    mode: str,
    checkpoint: str,
) -> None:
    prepared = _prepare_finalization(csr_workspace, mode)
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
        side_prepared = (
            prepared[0],
            root / prepared[1].relative_to(seed),
            prepared[2],
            root / prepared[3].relative_to(seed),
            root / prepared[4].relative_to(seed),
        )
        _crash_finalization(workspace, side_prepared, checkpoint)
        if python:
            result = _python_recover(workspace)
        else:
            result = process_runner(
                [BASH_RECOVER, "--namespace", workspace.namespace, "--yes"],
                env=environment(
                    isolated_environment,
                    PLATFORM_TOOLS_LIB_DIR=os.fspath(ORACLE_LIB),
                ),
                timeout=120,
            )
        results.append(result)

    assert (
        results[0].status,
        results[0].stdout,
        results[0].stderr,
    ) == (
        results[1].status,
        results[1].stdout,
        results[1].stderr,
    )
    normalizer = managed_openssl_dir_normalizer(seed, bash_root, python_root)
    assert snapshot_state(
        bash_root / "namespace/pki", (normalizer,)
    ) == snapshot_state(python_root / "namespace/pki", (normalizer,))


def test_frozen_csr_recover_oracle_remains_bash_owned() -> None:
    assert BASH_RECOVER.read_bytes().startswith(b"#!/usr/bin/env bash\n")
