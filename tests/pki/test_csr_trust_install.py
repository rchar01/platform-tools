from __future__ import annotations

import fcntl
import hashlib
import os
import shutil
import stat
import time
from collections.abc import Callable, Mapping
from pathlib import Path

import pytest

from ..harness import ManagedProcess, ProcessResult, run_process
from .migration_harness import run_differential_case
from .support import BIN, REPOSITORY, assert_result, digest, environment, executable, executable_directory, mode, write_executable, write_private
from .test_csr_candidate import POLICY2, REQUEST_ID, configure_deployer_trust, decide, prepare, publish_request
from .test_csr_signing import (
    EXPORT as ANSIBLE_EXPORT,
    INVENTORY,
    ISSUE,
    CsrWorkspace,
    RENEW,
    csr_workspace,
    write_exchange,
)


pytestmark = pytest.mark.pki
INIT = (BIN / "platform-pki", "init")
TOOL = (BIN / "platform-pki", "csr-trust-install")
UNIFIED = BIN / "platform-pki"
ORACLE_ROOT = REPOSITORY / "tests/pki/oracles/platform-pki-csr-trust-install"
ORACLE = ORACLE_ROOT / "platform-pki-csr-trust-install"
ORACLE_LIB = ORACLE_ROOT / "lib"
ORACLE_COMMIT = "678daa6de2ea24ada1fd36199013347f79f303bf"
ORACLE_HASHES = {
    "platform-pki-csr-trust-install": "280333e79c824ea6d1d4f159c36d6cf8573d6a13fd985144f7ba0b0b4fbefa40",
    "lib/platform-pki-common.sh": "dee644be8ab6236cb368a553493f55b53a90c3aead291550f7e635c080a5494f",
    "lib/platform-pki-csr-sign.sh": "8659a730f91c592c12fa3d40acbb080cf10d3eff6bd2de38fa486e8055f3e001",
    "lib/platform-pki-csr-candidate.sh": "ca1fb976f09730fbbc840ce97cb0c6db3ae76e5d679fdc777a1a96d80df5b43f",
}
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


def test_frozen_trust_install_oracle_matches_provenance_and_modes() -> None:
    plan = (REPOSITORY / "docs/plans/platform-pki-python-migration.md").read_text(
        encoding="utf-8"
    )
    assert ORACLE_COMMIT in plan
    assert {
        path.relative_to(ORACLE_ROOT).as_posix()
        for path in ORACLE_ROOT.rglob("*")
    } == {"lib", *ORACLE_HASHES}
    for relative, expected in ORACLE_HASHES.items():
        path = ORACLE_ROOT / relative
        assert path.is_file() and not path.is_symlink()
        assert hashlib.sha256(path.read_bytes()).hexdigest() == expected
        expected_mode = 0o644 if relative.startswith("lib/") else 0o755
        assert stat.S_IMODE(path.stat().st_mode) == expected_mode
        if expected_mode == 0o755:
            assert os.access(path, os.X_OK)


def run(process_runner: Callable[..., ProcessResult], env: Mapping[str, str], namespace: Path, private: Path, *arguments: object) -> ProcessResult:
    return process_runner(
        [*TOOL, "--namespace", namespace, "--private-repo", private, *arguments],
        env=env,
        timeout=30,
    )


def wait_for_path(
    path: Path, process: ManagedProcess, timeout: float = 30.0
) -> None:
    deadline = time.monotonic() + timeout
    while not path.exists():
        observation = process.observe()
        if observation.status is not None:
            pytest.fail(f"process exited before pause marker: {observation}")
        if time.monotonic() >= deadline:
            pytest.fail(f"timed out waiting for pause marker: {path}")
        time.sleep(0.01)


def start_paused(
    process_starter,
    env: Mapping[str, str],
    namespace: Path,
    private: Path,
    point: str,
    marker: Path,
    release: Path,
) -> ManagedProcess:
    return process_starter(
        [*TOOL, "--namespace", namespace, "--private-repo", private],
        env=environment(
            env,
            PLATFORM_PKI_CSR_TRUST_INSTALL_PAUSE_AT=point,
            PLATFORM_PKI_CSR_TRUST_INSTALL_PAUSE_MARKER=os.fspath(marker),
            PLATFORM_PKI_CSR_TRUST_INSTALL_PAUSE_RELEASE=os.fspath(release),
        ),
        timeout=30,
    )


def assert_operation_locks_available(namespace: Path) -> None:
    locks = []
    try:
        for name in ("lifecycle", "root", "intermediate", "inventory"):
            lock = (namespace / f"pki/locks/{name}").open("a+")
            locks.append(lock)
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        for lock in reversed(locks):
            fcntl.flock(lock, fcntl.LOCK_UN)
            lock.close()


def public_key(process_runner, env, root: Path, name: str) -> str:
    key = root / name
    result = process_runner(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key],
        env=env,
        timeout=30,
    )
    assert_result(result, 0)
    fields = key.with_suffix(".pub").read_text().split()
    return f"{fields[0]} {fields[1]}"


def setup_workspace(tmp_path: Path, process_runner, env) -> tuple[Path, Path, Path]:
    namespace = tmp_path / "namespace"
    assert_result(process_runner([*INIT, "--namespace", namespace], env=env, timeout=30), 0)
    private = tmp_path / "platform-private"
    trust = private / "pki/csr-trust"
    trust.mkdir(mode=0o700, parents=True)
    private.chmod(0o700)
    (private / "pki").chmod(0o700)
    keys = tmp_path / "keys"
    keys.mkdir(mode=0o700)
    requester = public_key(process_runner, env, keys, "requester")
    approver = public_key(process_runner, env, keys, "approver")
    response = public_key(process_runner, env, keys, "response")
    write_private(trust / "policy", POLICY)
    write_private(trust / "requesters.allowed_signers", f"host-01 {requester}\n")
    write_private(trust / "approvers.allowed_signers", f"offline-approver {approver}\n")
    write_private(trust / "responses.allowed_signers", f"offline-response {response}\n")
    return namespace, private, keys


def _normalize_case_root(root: Path, output: str) -> str:
    return output.replace(os.fspath(root), "<CASE>")


def _differential_seed(
    tmp_path: Path,
    process_runner,
    isolated_environment: Mapping[str, str],
    *,
    installed: bool = False,
    changed: bool = False,
) -> Path:
    seed = tmp_path / "seed"
    seed.mkdir(mode=0o700)
    namespace, private, keys = setup_workspace(
        seed, process_runner, isolated_environment
    )
    if installed:
        result = process_runner(
            [
                ORACLE,
                "--namespace",
                namespace,
                "--private-repo",
                private,
            ],
            env=environment(
                isolated_environment,
                PLATFORM_TOOLS_LIB_DIR=os.fspath(ORACLE_LIB),
            ),
            timeout=30,
        )
        assert_result(result, 0)
    if changed:
        replacement = public_key(
            process_runner,
            isolated_environment,
            keys,
            "differential-requester",
        )
        write_private(
            private / "pki/csr-trust/requesters.allowed_signers",
            f"host-01 {replacement}\n",
        )
    return seed


def _run_trust_install_differential(
    seed: Path,
    case_root: Path,
    isolated_environment: Mapping[str, str],
):
    def command(root: Path, tool: tuple[Path | str, ...]):
        return (
            *tool,
            "--namespace",
            root / "namespace",
            "--private-repo",
            root / "platform-private",
        )

    return run_differential_case(
        seed,
        case_root,
        Path("namespace/pki"),
        lambda root: command(root, (ORACLE,)),
        lambda root: command(root, (UNIFIED, "csr-trust-install")),
        environment(
            isolated_environment,
            PLATFORM_TOOLS_LIB_DIR=os.fspath(ORACLE_LIB),
        ),
        output_normalizers=(_normalize_case_root,),
        runner=run_process,
        run_options={"timeout": 30},
    )


@pytest.mark.parametrize(
    ("installed", "changed"),
    (
        pytest.param(False, False, id="fresh-install"),
        pytest.param(True, False, id="exact-noop"),
        pytest.param(True, True, id="atomic-update"),
    ),
)
def test_bash_python_trust_install_is_equivalent(
    tmp_path,
    process_runner,
    isolated_environment,
    installed: bool,
    changed: bool,
) -> None:
    seed = _differential_seed(
        tmp_path,
        process_runner,
        isolated_environment,
        installed=installed,
        changed=changed,
    )
    result = _run_trust_install_differential(
        seed, tmp_path / "differential", isolated_environment
    )
    result.assert_equivalent()


def test_install_noop_and_atomic_update(tmp_path, process_runner, isolated_environment) -> None:
    namespace, private, keys = setup_workspace(tmp_path, process_runner, isolated_environment)
    destination = namespace / "pki/inventory/csr-trust"

    result = run(process_runner, isolated_environment, namespace, private)
    assert_result(result, 0, stderr="")
    assert "CSR trust installed:" in result.stdout
    assert sorted(path.name for path in destination.iterdir()) == [
        "approvers.allowed_signers", "policy", "requesters.allowed_signers", "responses.allowed_signers"
    ]
    assert mode(destination) == 0o700
    assert all(mode(path) == 0o600 for path in destination.iterdir())
    inode = destination.stat().st_ino

    result = run(process_runner, isolated_environment, namespace, private)
    assert_result(result, 0, stderr="")
    assert "CSR trust already current:" in result.stdout
    assert destination.stat().st_ino == inode

    replacement = public_key(process_runner, isolated_environment, keys, "requester-new")
    write_private(private / "pki/csr-trust/requesters.allowed_signers", f"host-01 {replacement}\n")
    result = run(process_runner, isolated_environment, namespace, private)
    assert_result(result, 0, stderr="")
    assert "CSR trust updated:" in result.stdout
    assert destination.stat().st_ino != inode
    assert replacement in (destination / "requesters.allowed_signers").read_text()


def test_default_parent_relative_private_repo(
    tmp_path, process_runner, isolated_environment
) -> None:
    namespace, _, _ = setup_workspace(
        tmp_path, process_runner, isolated_environment
    )
    controller = tmp_path / "controller"
    controller.mkdir(mode=0o700)

    result = process_runner(
        [*TOOL, "--namespace", namespace],
        cwd=controller,
        env=isolated_environment,
        timeout=30,
    )

    assert_result(result, 0)
    assert (namespace / "pki/inventory/csr-trust").is_dir()


def test_noop_rechecks_each_installed_trust_file(
    tmp_path, process_runner, process_starter, isolated_environment
) -> None:
    namespace, private, _ = setup_workspace(
        tmp_path, process_runner, isolated_environment
    )
    assert_result(run(process_runner, isolated_environment, namespace, private), 0)
    installed = namespace / "pki/inventory/csr-trust/responses.allowed_signers"
    marker = tmp_path / "noop-installed-race.marker"
    release = tmp_path / "noop-installed-race.release"
    process = start_paused(
        process_starter,
        isolated_environment,
        namespace,
        private,
        "csr-trust-before-noop-installed-recheck",
        marker,
        release,
    )
    wait_for_path(marker, process)
    installed.write_bytes(installed.read_bytes() + b"\n")
    release.touch()
    result = process.wait()

    assert result.status == 1
    assert marker.is_file()
    assert "CSR trust already current:" not in result.stdout


def test_update_rechecks_installed_trust_after_final_state_digest(
    csr_workspace: CsrWorkspace, process_starter, tmp_path
) -> None:
    workspace = csr_workspace
    artifact, manifest_digest = prepare(workspace)
    assert_result(
        decide(
            workspace,
            REQUEST_ID,
            artifact,
            manifest_digest,
            action="finalize",
            result="activated",
        ),
        0,
    )
    destination = workspace.pki / "inventory/csr-trust"
    destination_inode = destination.stat().st_ino
    deployer_before = digest(destination / "deployers.allowed_signers")
    installed = destination / "responses.allowed_signers"
    replace_deployer_trust(workspace)
    marker = tmp_path / "update-installed-race.marker"
    release = tmp_path / "update-installed-race.release"
    process = start_paused(
        process_starter,
        workspace.env,
        workspace.namespace,
        workspace.private,
        "replacement-before-final-authorization",
        marker,
        release,
    )
    wait_for_path(marker, process)
    installed.write_bytes(installed.read_bytes() + b"\n")
    release.touch()
    result = process.wait()

    assert result.status == 1
    assert marker.is_file()
    assert destination.stat().st_ino == destination_inode
    assert digest(destination / "deployers.allowed_signers") == deployer_before


@pytest.mark.parametrize(
    ("case", "message"),
    (
        pytest.param("options", "no-options Ed25519", id="options"),
        pytest.param("wrong-algorithm", "no-options Ed25519", id="algorithm"),
        pytest.param("wrong-policy", "request maximum age must be 604800", id="policy"),
        pytest.param("extra-file", "must contain exactly policy", id="extra-file"),
        pytest.param("missing-principal", "does not contain required principal", id="principal"),
        pytest.param("duplicate-principal", "contains duplicate principal", id="duplicate-principal"),
        pytest.param("extra-token", "no-options Ed25519", id="extra-token"),
        pytest.param("invalid-key", "invalid Ed25519 public key", id="invalid-key"),
        pytest.param("empty-signers", "bounded ASCII text", id="empty-signers"),
        pytest.param("additional-approver", "exactly the pinned principal", id="additional-approver"),
        pytest.param("additional-response", "exactly the pinned principal", id="additional-response"),
        pytest.param("missing-file", "must contain exactly policy", id="missing-file"),
        pytest.param("non-ascii", "bounded ASCII text", id="non-ascii"),
        pytest.param("no-trailing-newline", "bounded ASCII text", id="no-trailing-newline"),
        pytest.param("blank-line", "bounded ASCII text", id="blank-line"),
        pytest.param("reordered-policy", "schema must be 1", id="reordered-policy"),
    ),
)
def test_invalid_trust_is_rejected_without_replacing_installed_state(tmp_path, process_runner, isolated_environment, case: str, message: str) -> None:
    namespace, private, _ = setup_workspace(tmp_path, process_runner, isolated_environment)
    assert_result(run(process_runner, isolated_environment, namespace, private), 0)
    destination = namespace / "pki/inventory/csr-trust"
    before = {path.name: digest(path) for path in destination.iterdir()}
    trust = private / "pki/csr-trust"
    if case == "options":
        path = trust / "requesters.allowed_signers"
        path.write_text(f'cert-authority {path.read_text()}')
    elif case == "wrong-algorithm":
        (trust / "requesters.allowed_signers").write_text("host-01 ssh-rsa AAAA\n")
    elif case == "wrong-policy":
        path = trust / "policy"
        path.write_text(path.read_text().replace("request_max_age_seconds=604800", "request_max_age_seconds=1"))
    elif case == "extra-file":
        write_private(trust / "extra", "unexpected\n")
    elif case == "missing-principal":
        path = trust / "approvers.allowed_signers"
        path.write_text(path.read_text().replace("offline-approver", "other-approver"))
    elif case == "duplicate-principal":
        path = trust / "requesters.allowed_signers"
        path.write_text(path.read_text() * 2)
    elif case == "extra-token":
        path = trust / "requesters.allowed_signers"
        path.write_text(path.read_text().rstrip() + " comment\n")
    elif case == "invalid-key":
        (trust / "requesters.allowed_signers").write_text("host-01 ssh-ed25519 AAAA\n")
    elif case == "empty-signers":
        (trust / "requesters.allowed_signers").write_text("")
    elif case == "additional-approver":
        path = trust / "approvers.allowed_signers"
        path.write_text(path.read_text() + (trust / "requesters.allowed_signers").read_text())
    elif case == "additional-response":
        path = trust / "responses.allowed_signers"
        path.write_text(path.read_text() + (trust / "requesters.allowed_signers").read_text())
    elif case == "missing-file":
        (trust / "responses.allowed_signers").unlink()
    elif case == "non-ascii":
        path = trust / "requesters.allowed_signers"
        path.write_bytes(path.read_bytes() + b"\xc3\xa9\n")
    elif case == "no-trailing-newline":
        path = trust / "requesters.allowed_signers"
        path.write_text(path.read_text().rstrip("\n"))
    elif case == "blank-line":
        path = trust / "requesters.allowed_signers"
        path.write_text(path.read_text() + "\n")
    else:
        path = trust / "policy"
        lines = path.read_text().splitlines()
        lines[0], lines[1] = lines[1], lines[0]
        path.write_text("\n".join(lines) + "\n")
    for path in trust.iterdir():
        path.chmod(0o600)

    result = run(process_runner, isolated_environment, namespace, private)

    assert result.status == 1
    assert message in result.stderr
    assert {path.name: digest(path) for path in destination.iterdir()} == before


@pytest.mark.parametrize(
    "name",
    ("policy", "requesters.allowed_signers", "approvers.allowed_signers", "responses.allowed_signers"),
)
def test_each_source_replacement_during_staging_is_rejected(
    tmp_path, process_runner, process_starter, isolated_environment, name: str
) -> None:
    namespace, private, keys = setup_workspace(tmp_path, process_runner, isolated_environment)
    assert_result(run(process_runner, isolated_environment, namespace, private), 0)
    destination = namespace / "pki/inventory/csr-trust"
    before = {path.name: digest(path) for path in destination.iterdir()}
    source = private / "pki/csr-trust" / name
    replacement = tmp_path / f"{name}.replacement"
    if name == "policy":
        write_private(replacement, POLICY)
    else:
        principal = {"requesters.allowed_signers": "host-01", "approvers.allowed_signers": "offline-approver", "responses.allowed_signers": "offline-response"}[name]
        key_name = name.split(".", 1)[0] + "-replacement"
        write_private(replacement, f"{principal} {public_key(process_runner, isolated_environment, keys, key_name)}\n")
    marker = tmp_path / f"{name}.marker"
    release = tmp_path / f"{name}.release"
    process = start_paused(
        process_starter,
        isolated_environment,
        namespace,
        private,
        "csr-trust-after-stage-before-source-recheck",
        marker,
        release,
    )
    wait_for_path(marker, process)
    replacement.replace(source)
    release.touch()
    result = process.wait()

    assert result.status == 1
    assert marker.is_file()
    assert "CSR trust source changed during installation" in result.stderr
    assert {path.name: digest(path) for path in destination.iterdir()} == before
    assert not tuple(
        (namespace / "pki/inventory").glob(".platform-pki-csr-trust.*")
    )


def test_public_key_validation_cleanup_preserves_foreign_replacement(
    tmp_path, process_runner, process_starter, isolated_environment
) -> None:
    namespace, private, _ = setup_workspace(tmp_path, process_runner, isolated_environment)
    temporary = tmp_path / "public-key-validation-tmp"
    temporary.mkdir(mode=0o700)
    foreign = tmp_path / "foreign-public-key-validation"
    write_private(foreign, "foreign public key validation file\n")
    metadata = foreign.lstat()
    before = (metadata.st_mode, metadata.st_uid, metadata.st_gid, metadata.st_ino, metadata.st_nlink, metadata.st_size, metadata.st_mtime_ns, digest(foreign))
    displaced = tmp_path / "displaced-public-key-validation"
    marker = tmp_path / "public-key-validation-race.marker"
    release = tmp_path / "public-key-validation-race.release"
    process = start_paused(
        process_starter,
        environment(
            isolated_environment,
            TMPDIR=os.fspath(temporary),
        ),
        namespace,
        private,
        "csr-trust-public-key-before-validation",
        marker,
        release,
    )
    wait_for_path(marker, process)
    staged = tuple(
        temporary.glob("platform-pki-csr-public-key.*/.public-key.stage-*")
    )
    assert len(staged) == 1
    staged[0].replace(displaced)
    foreign.replace(staged[0])
    release.touch()
    result = process.wait()

    retained = tuple(temporary.glob("platform-pki-csr-public-key.*"))
    assert len(retained) == 1
    retained_file = retained[0] / staged[0].name
    metadata = retained_file.lstat()
    after = (metadata.st_mode, metadata.st_uid, metadata.st_gid, metadata.st_ino, metadata.st_nlink, metadata.st_size, metadata.st_mtime_ns, digest(retained_file))
    assert result.status == 1
    assert "Cannot stage CSR trust public-key validation" in result.stderr
    assert marker.is_file()
    assert displaced.is_file()
    assert after == before
    assert not (namespace / "pki/inventory/csr-trust").exists()


def test_installed_destination_replacement_before_exchange_is_rejected(
    tmp_path, process_runner, process_starter, isolated_environment
) -> None:
    namespace, private, keys = setup_workspace(tmp_path, process_runner, isolated_environment)
    assert_result(run(process_runner, isolated_environment, namespace, private), 0)
    inventory = namespace / "pki/inventory"
    destination = inventory / "csr-trust"
    replacement = tmp_path / "destination-replacement"
    displaced = tmp_path / "destination-displaced"
    shutil.copytree(destination, replacement, copy_function=shutil.copy2)
    new_key = public_key(process_runner, isolated_environment, keys, "requester-destination-race")
    write_private(private / "pki/csr-trust/requesters.allowed_signers", f"host-01 {new_key}\n")
    marker = tmp_path / "destination-race.marker"
    release = tmp_path / "destination-race.release"
    process = start_paused(
        process_starter,
        isolated_environment,
        namespace,
        private,
        "replacement-before-exchange",
        marker,
        release,
    )
    wait_for_path(marker, process)
    destination.replace(displaced)
    replacement.replace(destination)
    release.touch()
    result = process.wait()

    assert result.status == 1
    assert marker.is_file()
    assert "Publication object identity changed" in result.stderr
    assert displaced.is_dir()
    assert new_key not in (destination / "requesters.allowed_signers").read_text()
    assert not tuple(inventory.glob(".platform-pki-csr-trust.*"))


def test_final_authorization_rejects_destination_replacement(
    tmp_path, process_runner, process_starter, isolated_environment
) -> None:
    namespace, private, keys = setup_workspace(tmp_path, process_runner, isolated_environment)
    assert_result(run(process_runner, isolated_environment, namespace, private), 0)
    inventory = namespace / "pki/inventory"
    destination = inventory / "csr-trust"
    displaced = tmp_path / "destination-displaced-at-exchange"
    foreign = tmp_path / "foreign-destination"
    shutil.copytree(destination, foreign, copy_function=shutil.copy2)
    write_private(foreign / "foreign-owned", "must survive failed exchange\n")
    foreign_inode = foreign.stat().st_ino
    new_key = public_key(process_runner, isolated_environment, keys, "requester-exchange-race")
    write_private(private / "pki/csr-trust/requesters.allowed_signers", f"host-01 {new_key}\n")
    marker = tmp_path / "exchange-destination-race.marker"
    release = tmp_path / "exchange-destination-race.release"
    process = start_paused(
        process_starter,
        isolated_environment,
        namespace,
        private,
        "replacement-before-final-authorization",
        marker,
        release,
    )
    wait_for_path(marker, process)
    destination.replace(displaced)
    foreign.replace(destination)
    release.touch()
    result = process.wait()

    retained = tuple(inventory.glob(".platform-pki-csr-trust.*"))
    assert result.status == 1
    assert result.stdout == ""
    assert "Installed CSR trust" in result.stderr
    assert marker.is_file()
    assert displaced.is_dir()
    assert not retained
    assert destination.stat().st_ino == foreign_inode
    assert (destination / "foreign-owned").read_text() == "must survive failed exchange\n"
    assert new_key not in (destination / "requesters.allowed_signers").read_text()


@pytest.mark.parametrize(
    "fault_point",
    (
        "replacement-after-exchange",
        "replacement-after-exchange-durability",
        "tree-cleanup-before-mutation",
    ),
)
def test_update_interruptions_leave_one_complete_trust_tree(
    tmp_path, process_runner, isolated_environment, fault_point: str
) -> None:
    namespace, private, keys = setup_workspace(tmp_path, process_runner, isolated_environment)
    assert_result(run(process_runner, isolated_environment, namespace, private), 0)
    inventory = namespace / "pki/inventory"
    destination = inventory / "csr-trust"
    prior_requester = (destination / "requesters.allowed_signers").read_text()
    new_key = public_key(process_runner, isolated_environment, keys, f"requester-{fault_point}")
    write_private(private / "pki/csr-trust/requesters.allowed_signers", f"host-01 {new_key}\n")
    result = run(
        process_runner,
        environment(
            isolated_environment,
            PLATFORM_PKI_CSR_TRUST_INSTALL_FAILURE_AT=fault_point,
        ),
        namespace,
        private,
    )

    assert result.status == 1
    assert sorted(path.name for path in destination.iterdir()) == [
        "approvers.allowed_signers", "policy", "requesters.allowed_signers", "responses.allowed_signers"
    ]
    assert new_key in (destination / "requesters.allowed_signers").read_text()
    retained = tuple(inventory.glob(".platform-pki-csr-trust.*"))
    assert len(retained) == 1
    assert sorted(path.name for path in retained[0].iterdir()) == [
        "approvers.allowed_signers", "policy", "requesters.allowed_signers", "responses.allowed_signers"
    ]
    assert (retained[0] / "requesters.allowed_signers").read_text() == prior_requester


@pytest.mark.parametrize("case", ("symlink", "hardlink", "writable"))
def test_unsafe_source_is_rejected(tmp_path, process_runner, isolated_environment, case: str) -> None:
    namespace, private, _ = setup_workspace(tmp_path, process_runner, isolated_environment)
    source = private / "pki/csr-trust/requesters.allowed_signers"
    if case == "symlink":
        target = source.with_name("requesters.real")
        source.rename(target)
        source.symlink_to(target)
    elif case == "hardlink":
        os.link(source, source.with_name("requesters.link"))
    else:
        source.chmod(0o622)

    result = run(process_runner, isolated_environment, namespace, private)

    assert result.status == 1
    assert not (namespace / "pki/inventory/csr-trust").exists()


def test_failed_exchange_preserves_installed_trust(tmp_path, process_runner, isolated_environment) -> None:
    namespace, private, keys = setup_workspace(tmp_path, process_runner, isolated_environment)
    assert_result(run(process_runner, isolated_environment, namespace, private), 0)
    destination = namespace / "pki/inventory/csr-trust"
    before = digest(destination / "requesters.allowed_signers")
    replacement = public_key(process_runner, isolated_environment, keys, "requester-failure")
    write_private(private / "pki/csr-trust/requesters.allowed_signers", f"host-01 {replacement}\n")
    result = run(
        process_runner,
        environment(
            isolated_environment,
            PLATFORM_PKI_CSR_TRUST_INSTALL_FAILURE_AT="replacement-before-exchange",
        ),
        namespace,
        private,
    )

    assert result.status == 1
    assert digest(destination / "requesters.allowed_signers") == before
    assert not tuple((namespace / "pki/inventory").glob(".platform-pki-csr-trust.*"))


def test_ambiguous_initial_publication_reports_both_possible_locations(
    tmp_path, process_runner, isolated_environment
) -> None:
    namespace, private, _ = setup_workspace(
        tmp_path, process_runner, isolated_environment
    )
    inventory = namespace / "pki/inventory"
    destination = inventory / "csr-trust"

    result = run(
        process_runner,
        environment(
            isolated_environment,
            PLATFORM_PKI_CSR_TRUST_INSTALL_FAILURE_AT="publication-after-mutation",
        ),
        namespace,
        private,
    )

    assert result.status == 1
    assert destination.is_dir()
    assert sorted(path.name for path in destination.iterdir()) == [
        "approvers.allowed_signers",
        "policy",
        "requesters.allowed_signers",
        "responses.allowed_signers",
    ]
    assert f"retained evidence may be at: {destination} or " in result.stderr
    assert f"{inventory}/.platform-pki-csr-trust." in result.stderr


def test_initial_publication_rechecks_source_immediately_before_rename(
    tmp_path, process_runner, process_starter, isolated_environment
) -> None:
    namespace, private, _ = setup_workspace(
        tmp_path, process_runner, isolated_environment
    )
    source = private / "pki/csr-trust/requesters.allowed_signers"
    marker = tmp_path / "initial-publication-source-race.marker"
    release = tmp_path / "initial-publication-source-race.release"
    process = start_paused(
        process_starter,
        isolated_environment,
        namespace,
        private,
        "publication-before-mutation",
        marker,
        release,
    )
    wait_for_path(marker, process)
    source.chmod(0o622)
    release.touch()
    result = process.wait()

    assert result.status == 1
    assert "CSR trust source must be a readable non-symlink regular file" in result.stderr
    inventory = namespace / "pki/inventory"
    assert not (inventory / "csr-trust").exists()
    assert not tuple(inventory.glob(".platform-pki-csr-trust.*"))


def test_source_change_during_staging_is_rejected(tmp_path, process_runner, process_starter, isolated_environment) -> None:
    namespace, private, _ = setup_workspace(tmp_path, process_runner, isolated_environment)
    assert_result(run(process_runner, isolated_environment, namespace, private), 0)
    destination = namespace / "pki/inventory/csr-trust"
    before = {path.name: digest(path) for path in destination.iterdir()}
    source = private / "pki/csr-trust/requesters.allowed_signers"
    marker = tmp_path / "source-race.marker"
    release = tmp_path / "source-race.release"
    process = start_paused(
        process_starter,
        isolated_environment,
        namespace,
        private,
        "csr-trust-after-stage-before-source-recheck",
        marker,
        release,
    )
    wait_for_path(marker, process)
    source.chmod(0o622)
    release.touch()
    result = process.wait()

    assert result.status == 1
    assert (
        "CSR trust source must be a readable non-symlink regular file: "
        f"{source}"
    ) in result.stderr
    assert {path.name: digest(path) for path in destination.iterdir()} == before
    assert not tuple(
        (namespace / "pki/inventory").glob(".platform-pki-csr-trust.*")
    )


def test_unsafe_installed_trust_is_not_replaced(tmp_path, process_runner, isolated_environment) -> None:
    namespace, private, keys = setup_workspace(tmp_path, process_runner, isolated_environment)
    assert_result(run(process_runner, isolated_environment, namespace, private), 0)
    destination = namespace / "pki/inventory/csr-trust"
    installed = destination / "requesters.allowed_signers"
    installed.chmod(0o644)
    before = digest(installed)
    replacement = public_key(process_runner, isolated_environment, keys, "requester-unsafe-destination")
    write_private(private / "pki/csr-trust/requesters.allowed_signers", f"host-01 {replacement}\n")

    result = run(process_runner, isolated_environment, namespace, private)

    assert result.status == 1
    assert f"Installed CSR trust file is unsafe: {installed}" in result.stderr
    assert digest(installed) == before
    assert mode(installed) == 0o644


@pytest.mark.parametrize(
    ("name", "label"),
    (
        pytest.param("lifecycle", "PKI lifecycle operation", id="lifecycle"),
        pytest.param("root", "root CA operation", id="root"),
        pytest.param("intermediate", "intermediate CA operation", id="intermediate"),
        pytest.param("inventory", "inventory operation", id="inventory"),
    ),
)
def test_each_operation_lock_blocks_installation(
    tmp_path, process_runner, isolated_environment, name: str, label: str
) -> None:
    namespace, private, _ = setup_workspace(
        tmp_path, process_runner, isolated_environment
    )
    lock_path = namespace / f"pki/locks/{name}"
    with lock_path.open("a+") as lock:
        lock_path.chmod(0o600)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = run(
            process_runner, isolated_environment, namespace, private
        )

    assert result.status == 1
    assert f"Another {label} is in progress: {lock_path}" in result.stderr
    assert not (namespace / "pki/inventory/csr-trust").exists()


@pytest.mark.parametrize("case", ("success", "failure"))
def test_operation_locks_are_available_after_completion(
    tmp_path,
    process_runner,
    isolated_environment,
    case: str,
) -> None:
    namespace, private, _ = setup_workspace(
        tmp_path, process_runner, isolated_environment
    )
    if case == "failure":
        assert_result(
            run(process_runner, isolated_environment, namespace, private), 0
        )
        (namespace / "pki/inventory/csr-trust/policy").chmod(0o644)
    result = run(
        process_runner,
        isolated_environment,
        namespace,
        private,
    )

    assert result.status == (0 if case == "success" else 1)
    assert_operation_locks_available(namespace)


def test_root_contention_releases_lifecycle_lock(
    tmp_path, process_runner, isolated_environment
) -> None:
    namespace, private, _ = setup_workspace(
        tmp_path, process_runner, isolated_environment
    )
    root_lock = namespace / "pki/locks/root"
    with root_lock.open("a+") as lock:
        root_lock.chmod(0o600)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = run(
            process_runner, isolated_environment, namespace, private
        )
        with (namespace / "pki/locks/lifecycle").open("a+") as lifecycle:
            fcntl.flock(lifecycle, fcntl.LOCK_EX | fcntl.LOCK_NB)

    assert result.status == 1
    assert f"Another root CA operation is in progress: {root_lock}" in result.stderr


def replace_deployer_trust(workspace: CsrWorkspace) -> None:
    fields = workspace.response_key.with_suffix(".pub").read_text().split()
    write_private(
        workspace.private / "pki/csr-trust/deployers.allowed_signers",
        f"host-01 {fields[0]} {fields[1]}\n",
    )


def test_initial_schema_two_install_succeeds_without_candidate_state(
    tmp_path, process_runner, isolated_environment
) -> None:
    namespace, private, keys = setup_workspace(
        tmp_path, process_runner, isolated_environment
    )
    trust = private / "pki/csr-trust"
    fields = (keys / "requester.pub").read_text().split()
    write_private(trust / "policy", POLICY2)
    write_private(
        trust / "deployers.allowed_signers",
        f"host-01 {fields[0]} {fields[1]}\n",
    )

    result = run(process_runner, isolated_environment, namespace, private)

    assert_result(result, 0)
    assert "CSR trust installed:" in result.stdout


def test_initial_schema_two_install_and_pending_exact_noop(
    csr_workspace: CsrWorkspace,
) -> None:
    workspace = csr_workspace
    configure_deployer_trust(workspace)
    result = run(
        workspace.runner, workspace.env, workspace.namespace, workspace.private
    )
    assert_result(result, 0)
    assert "CSR trust updated:" in result.stdout
    assert_result(workspace.issue(), 0)

    result = run(
        workspace.runner, workspace.env, workspace.namespace, workspace.private
    )

    assert_result(result, 0)
    assert "CSR trust already current:" in result.stdout


@pytest.mark.parametrize(
    "transition", ("schema-one-to-two", "schema-two-update", "schema-two-to-one")
)
def test_pending_candidate_blocks_actual_schema_two_trust_change(
    csr_workspace: CsrWorkspace, transition: str
) -> None:
    workspace = csr_workspace
    if transition != "schema-one-to-two":
        configure_deployer_trust(workspace)
        assert_result(
            run(
                workspace.runner,
                workspace.env,
                workspace.namespace,
                workspace.private,
            ),
            0,
        )
    assert_result(workspace.issue(), 0)
    if transition == "schema-one-to-two":
        configure_deployer_trust(workspace)
    elif transition == "schema-two-update":
        replace_deployer_trust(workspace)
    else:
        trust = workspace.private / "pki/csr-trust"
        (trust / "deployers.allowed_signers").unlink()
        write_private(trust / "policy", POLICY)

    result = run(
        workspace.runner, workspace.env, workspace.namespace, workspace.private
    )

    assert result.status == 1
    assert f"pending candidate: external/{REQUEST_ID}" in result.stderr


@pytest.mark.parametrize(
    ("action", "result_name"),
    (
        pytest.param("finalize", "activated", id="finalized"),
        pytest.param("abandon", "not-activated", id="abandoned"),
    ),
)
def test_authenticated_terminal_history_allows_schema_two_rotation(
    csr_workspace: CsrWorkspace,
    action: str,
    result_name: str,
) -> None:
    workspace = csr_workspace
    artifact, manifest_digest = prepare(workspace)
    assert_result(
        decide(
            workspace,
            REQUEST_ID,
            artifact,
            manifest_digest,
            action=action,
            result=result_name,
        ),
        0,
    )
    replace_deployer_trust(workspace)

    result = run(
        workspace.runner, workspace.env, workspace.namespace, workspace.private
    )

    assert_result(result, 0)
    assert "CSR trust updated:" in result.stdout


def test_bash_python_terminal_history_uses_retained_roots_across_rotation(
    csr_workspace: CsrWorkspace,
    tmp_path,
) -> None:
    workspace = csr_workspace
    artifact, manifest_digest = prepare(workspace)
    assert_result(
        decide(
            workspace,
            REQUEST_ID,
            artifact,
            manifest_digest,
            action="finalize",
            result="activated",
        ),
        0,
    )
    trust = workspace.private / "pki/csr-trust"
    rotations = (
        ("requesters.allowed_signers", "host-01", "requester"),
        ("approvers.allowed_signers", "offline-approver", "approver"),
        ("responses.allowed_signers", "offline-response", "response"),
        ("deployers.allowed_signers", "host-01", "deployer"),
    )
    for file_name, principal, key_name in rotations:
        replacement = public_key(
            workspace.runner,
            workspace.env,
            tmp_path,
            f"rotated-{key_name}",
        )
        write_private(trust / file_name, f"{principal} {replacement}\n")

    seed = workspace.namespace.parent
    case_root = tmp_path.parent / f"{tmp_path.name}-trust-rotation-differential"
    result = _run_trust_install_differential(seed, case_root, workspace.env)

    result.assert_equivalent()


def test_terminal_history_fails_closed_without_current_inventory_binding(
    csr_workspace: CsrWorkspace,
) -> None:
    workspace = csr_workspace
    artifact, manifest_digest = prepare(workspace)
    assert_result(
        decide(
            workspace,
            REQUEST_ID,
            artifact,
            manifest_digest,
            action="finalize",
            result="activated",
        ),
        0,
    )
    write_private(
        workspace.pki / "inventory/services.yml",
        "services:\n"
        "  other:\n"
        "    common_name: other.example.internal\n"
        "    dns:\n"
        "      - other.example.internal\n",
    )
    replace_deployer_trust(workspace)

    result = run(
        workspace.runner, workspace.env, workspace.namespace, workspace.private
    )

    assert result.status == 1
    assert result.stderr == (
        "[ERROR] Retained CSR candidate service is absent from current inventory: "
        "external\n"
    )


def test_terminal_history_allows_unrelated_current_inventory_addition(
    csr_workspace: CsrWorkspace,
) -> None:
    workspace = csr_workspace
    artifact, manifest_digest = prepare(workspace)
    assert_result(
        decide(
            workspace,
            REQUEST_ID,
            artifact,
            manifest_digest,
            action="finalize",
            result="activated",
        ),
        0,
    )
    inventory = workspace.pki / "inventory/services.yml"
    historical = inventory.read_bytes()
    history = workspace.pki / "inventory/history"
    history.mkdir(mode=0o700)
    write_private(
        history / f"{hashlib.sha256(historical).hexdigest()}.yml",
        historical.decode("ascii"),
    )
    write_private(
        inventory,
        historical.decode("ascii")
        + "  unrelated:\n"
        + "    common_name: unrelated.example.internal\n"
        + "    dns:\n"
        + "      - unrelated.example.internal\n",
    )
    replace_deployer_trust(workspace)

    result = run(
        workspace.runner, workspace.env, workspace.namespace, workspace.private
    )

    assert_result(result, 0)
    assert "CSR trust updated:" in result.stdout


def test_superseded_terminal_history_allows_schema_two_rotation(
    csr_workspace: CsrWorkspace,
) -> None:
    workspace = csr_workspace
    first_artifact, first_manifest = prepare(workspace)
    assert_result(
        decide(
            workspace,
            REQUEST_ID,
            first_artifact,
            first_manifest,
            action="finalize",
            result="activated",
        ),
        0,
    )
    renewal_id = "2123456789abcdef0123456789abcdef"
    current = first_artifact / "tls.crt"
    write_exchange(workspace, "renew", renewal_id, "cd" * 32, digest(current))
    assert_result(workspace.sign(RENEW, current_cert=current), 0)
    renewal_artifact, renewal_manifest = publish_request(workspace, renewal_id)
    assert_result(
        decide(
            workspace,
            renewal_id,
            renewal_artifact,
            renewal_manifest,
            action="finalize",
            result="activated",
        ),
        0,
    )
    replace_deployer_trust(workspace)

    result = run(
        workspace.runner, workspace.env, workspace.namespace, workspace.private
    )

    assert_result(result, 0)
    assert "CSR trust updated:" in result.stdout


def prepare_terminal_migration(workspace: CsrWorkspace) -> None:
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
                *ISSUE,
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
                *ANSIBLE_EXPORT,
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
    write_private(workspace.pki / "inventory/services.yml", INVENTORY)
    migration_id = "1123456789abcdef0123456789abcdef"
    write_exchange(
        workspace, "migrate", migration_id, "bc" * 32, digest(certificate)
    )
    configure_deployer_trust(workspace)
    assert_result(
        run(
            workspace.runner,
            workspace.env,
            workspace.namespace,
            workspace.private,
        ),
        0,
    )
    assert_result(workspace.issue(), 0)
    artifact, manifest_digest = publish_request(workspace, migration_id)
    assert_result(
        decide(
            workspace,
            migration_id,
            artifact,
            manifest_digest,
            action="finalize",
            result="activated",
        ),
        0,
    )


def test_terminal_migration_history_allows_rotation_with_preserved_state(
    csr_workspace: CsrWorkspace,
) -> None:
    workspace = csr_workspace
    prepare_terminal_migration(workspace)
    replace_deployer_trust(workspace)

    result = run(
        workspace.runner, workspace.env, workspace.namespace, workspace.private
    )

    assert_result(result, 0)
    assert "CSR trust updated:" in result.stdout


def test_migration_history_is_rechecked_at_publication_boundary(
    csr_workspace: CsrWorkspace,
    executable_directory,
    tmp_path,
) -> None:
    workspace = csr_workspace
    prepare_terminal_migration(workspace)
    destination = workspace.pki / "inventory/csr-trust"
    before = digest(destination / "deployers.allowed_signers")
    replace_deployer_trust(workspace)
    fake_bin = executable_directory / "migration-history-race"
    gate_marker = tmp_path / "migration-history-race.gate"
    marker = tmp_path / "migration-history-race.marker"
    write_executable(
        fake_bin / "ssh-keygen",
        """#!/usr/bin/env bash
set -euo pipefail
if [[ $* == *platform-pki-csr-deployment-v1* && ! -e $RACE_GATE_MARKER ]]; then
  : >"$RACE_GATE_MARKER"
elif [[ -e $RACE_GATE_MARKER && ! -e $RACE_MARKER ]]; then
  printf '\n' >>"$RACE_MANAGED_CERTIFICATE"
  : >"$RACE_MARKER"
fi
exec "$REAL_SSH_KEYGEN" "$@"
""",
    )

    result = run(
        workspace.runner,
        environment(
            workspace.env,
            PATH=f"{fake_bin}:{workspace.env['PATH']}",
            REAL_SSH_KEYGEN=executable("ssh-keygen"),
            RACE_GATE_MARKER=os.fspath(gate_marker),
            RACE_MARKER=os.fspath(marker),
            RACE_MANAGED_CERTIFICATE=os.fspath(
                workspace.pki / "services/external/certs/tls.crt"
            ),
        ),
        workspace.namespace,
        workspace.private,
    )

    assert result.status == 1
    assert marker.is_file()
    assert digest(destination / "deployers.allowed_signers") == before


@pytest.mark.parametrize("tamper", ("outcome", "active-pointer"))
def test_tampered_terminal_state_blocks_schema_two_rotation(
    csr_workspace: CsrWorkspace, tamper: str
) -> None:
    workspace = csr_workspace
    artifact, manifest_digest = prepare(workspace)
    assert_result(
        decide(
            workspace,
            REQUEST_ID,
            artifact,
            manifest_digest,
            action="finalize",
            result="activated",
        ),
        0,
    )
    if tamper == "outcome":
        decision = workspace.pki / f"state/csr/outcomes/external/{REQUEST_ID}/decision"
        decision.write_text(
            decision.read_text().replace("state=finalized\n", "state=abandoned\n")
        )
    else:
        active = workspace.pki / "state/csr/active/external"
        active.write_text(
            active.read_text().replace(
                f"request_id={REQUEST_ID}\n", "request_id=" + "f" * 32 + "\n"
            )
        )
    replace_deployer_trust(workspace)

    result = run(
        workspace.runner, workspace.env, workspace.namespace, workspace.private
    )

    assert result.status == 1
    assert "CSR trust updated:" not in result.stdout


@pytest.mark.parametrize(
    "race",
    (
        "staged-trust",
        "retained-request",
        "post-gate-state",
        "post-gate-inventory",
    ),
)
def test_candidate_gate_rechecks_staged_trust_and_retained_history(
    csr_workspace: CsrWorkspace,
    executable_directory,
    tmp_path,
    race: str,
) -> None:
    workspace = csr_workspace
    artifact, manifest_digest = prepare(workspace)
    assert_result(
        decide(
            workspace,
            REQUEST_ID,
            artifact,
            manifest_digest,
            action="finalize",
            result="activated",
        ),
        0,
    )
    destination = workspace.pki / "inventory/csr-trust"
    before = digest(destination / "deployers.allowed_signers")
    replace_deployer_trust(workspace)
    fake_bin = executable_directory / f"candidate-gate-race-{race}"
    marker = tmp_path / f"candidate-gate-race-{race}.marker"
    gate_marker = tmp_path / f"candidate-gate-race-{race}.gate"
    write_executable(
        fake_bin / "ssh-keygen",
        """#!/usr/bin/env bash
set -euo pipefail
if [[ $RACE_KIND == post-gate-* && $* == *platform-pki-csr-deployment-v1* && ! -e $RACE_GATE_MARKER ]]; then
  : >"$RACE_GATE_MARKER"
elif [[ $RACE_KIND == post-gate-* && -e $RACE_GATE_MARKER && ! -e $RACE_MARKER ]]; then
  if [[ $RACE_KIND == post-gate-state ]]; then
    mkdir -m 700 -- "$RACE_PKI/state/csr/outcomes/external/ffffffffffffffffffffffffffffffff"
  else
    printf '\n' >>"$RACE_INVENTORY_FILE"
  fi
  : >"$RACE_MARKER"
elif [[ $* == *platform-pki-csr-deployment-v1* && ! -e $RACE_MARKER ]]; then
  if [[ $RACE_KIND == staged-trust ]]; then
    for path in "$RACE_INVENTORY"/.platform-pki-csr-trust.*/deployers.allowed_signers; do
      [[ -f $path ]] || continue
      printf '\n' >>"$path"
      break
    done
  else
    printf '\n' >>"$RACE_RETAINED_REQUEST"
  fi
  : >"$RACE_MARKER"
fi
exec "$REAL_SSH_KEYGEN" "$@"
""",
    )

    result = run(
        workspace.runner,
        environment(
            workspace.env,
            PATH=f"{fake_bin}:{workspace.env['PATH']}",
            REAL_SSH_KEYGEN=executable("ssh-keygen"),
            RACE_KIND=race,
            RACE_MARKER=os.fspath(marker),
            RACE_GATE_MARKER=os.fspath(gate_marker),
            RACE_INVENTORY=os.fspath(workspace.pki / "inventory"),
            RACE_INVENTORY_FILE=os.fspath(
                workspace.pki / "inventory/services.yml"
            ),
            RACE_PKI=os.fspath(workspace.pki),
            RACE_RETAINED_REQUEST=os.fspath(
                workspace.pki / f"state/csr/transactions/csr-{REQUEST_ID}/request"
            ),
        ),
        workspace.namespace,
        workspace.private,
    )

    assert result.status == 1
    assert marker.is_file()
    assert digest(destination / "deployers.allowed_signers") == before


@pytest.mark.parametrize(
    "case",
    (
        "malformed-outcome",
        "orphan-outcome",
        "duplicate-request",
        "empty-candidate-service",
        "empty-outcome-service",
        "malformed-active",
        "recovery",
    ),
)
def test_ambiguous_or_recovery_required_candidate_state_blocks_rotation(
    csr_workspace: CsrWorkspace, case: str
) -> None:
    workspace = csr_workspace
    if case in {"malformed-outcome", "duplicate-request"}:
        assert_result(workspace.issue(), 0)
    if case == "malformed-outcome":
        outcome = workspace.pki / f"state/csr/outcomes/external/{REQUEST_ID}"
        outcome.mkdir(mode=0o700, parents=True)
        outcome.parent.chmod(0o700)
        outcome.parent.parent.chmod(0o700)
    elif case == "orphan-outcome":
        outcome = workspace.pki / "state/csr/outcomes/external/1123456789abcdef0123456789abcdef"
        outcome.mkdir(mode=0o700, parents=True)
        outcome.parent.chmod(0o700)
        outcome.parent.parent.chmod(0o700)
    elif case == "duplicate-request":
        candidates = workspace.pki / "state/csr/candidates"
        duplicate = candidates / f"other/{REQUEST_ID}"
        duplicate.parent.mkdir(mode=0o700)
        shutil.copytree(candidates / f"external/{REQUEST_ID}", duplicate)
    elif case == "empty-candidate-service":
        service = workspace.pki / "state/csr/candidates/external"
        service.mkdir(mode=0o700, parents=True)
        service.parent.chmod(0o700)
    elif case == "empty-outcome-service":
        service = workspace.pki / "state/csr/outcomes/external"
        service.mkdir(mode=0o700, parents=True)
        service.parent.chmod(0o700)
    elif case == "malformed-active":
        active = workspace.pki / "state/csr/active"
        active.mkdir(mode=0o700, parents=True)
        active.parent.chmod(0o700)
        write_private(active / "external", "malformed active pointer\n")
    else:
        write_private(
            workspace.pki / "state/csr/finalization-recovery-journal",
            "recovery required\n",
        )
    configure_deployer_trust(workspace)

    result = run(
        workspace.runner, workspace.env, workspace.namespace, workspace.private
    )

    assert result.status == 1
    assert "CSR trust updated:" not in result.stdout
