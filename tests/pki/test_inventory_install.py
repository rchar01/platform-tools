from __future__ import annotations

import hashlib
import fcntl
import os
import shutil
import time
from collections.abc import Callable, Mapping
from pathlib import Path

import pytest

from ..harness import ProcessResult, run_process
from .migration_harness import run_differential_case
from .support import BIN, REPOSITORY, assert_result, digest, environment, mode, write_private


pytestmark = pytest.mark.pki
INIT = BIN / "platform-pki-init"
TOOL = BIN / "platform-pki-inventory-install"
ORACLE = REPOSITORY / "tests/pki/oracles/platform-pki-inventory-install/platform-pki-inventory-install"
UNIFIED = BIN / "platform-pki"
ORACLE_COMMIT = "8c2e8e7ae46e9aedbda70a9035682aa9f1445dd1"
ORACLE_SHA256 = "9084754ca9a6906abdbd3b1f6cbe7230f17a55074dfd327a0403d8d7a9a77031"
COMMON_SHA256 = "dee644be8ab6236cb368a553493f55b53a90c3aead291550f7e635c080a5494f"
INTERFACES = (
    pytest.param((ORACLE,), id="bash-oracle"),
    pytest.param((TOOL,), id="python-compatibility"),
    pytest.param((UNIFIED, "inventory-install"), id="python-unified"),
)
INVENTORY = """services:
  api:
    common_name: api.example.internal
    dns:
      - api.example.internal
"""
UPDATED_INVENTORY = INVENTORY.rstrip() + "\n    days: 2\n"


def run(process_runner: Callable[..., ProcessResult], env: Mapping[str, str], namespace: Path, private: Path | None, *, cwd: Path | None = None) -> ProcessResult:
    arguments: list[object] = [TOOL, "--namespace", namespace]
    if private is not None:
        arguments.extend(("--private-repo", private))
    return process_runner(arguments, env=env, cwd=cwd, timeout=30)


def run_interface(process_runner: Callable[..., ProcessResult], env: Mapping[str, str], tool: tuple[Path | str, ...], namespace: Path, private: Path) -> ProcessResult:
    effective = dict(env)
    if tool == (ORACLE,):
        effective.setdefault("PLATFORM_TOOLS_LIB_DIR", os.fspath(REPOSITORY / "lib"))
    return process_runner(
        [*tool, "--namespace", namespace, "--private-repo", private],
        env=effective,
        timeout=30,
    )


def setup_workspace(tmp_path: Path, process_runner, env) -> tuple[Path, Path, Path]:
    namespace = tmp_path / "namespace"
    result = process_runner([INIT, "--namespace", namespace], env=env, timeout=30)
    assert_result(result, 0)
    private = tmp_path / "platform-private"
    private.mkdir(mode=0o700)
    (private / "pki").mkdir(mode=0o700)
    write_private(private / "pki/services.yml", INVENTORY)
    return namespace, namespace / "pki", private


def wait_for_path(path: Path, timeout: float = 30) -> None:
    deadline = time.monotonic() + timeout
    while not path.exists():
        if time.monotonic() >= deadline:
            pytest.fail(f"timed out waiting for pause marker: {path}", pytrace=False)
        time.sleep(0.01)


def start_paused(process_starter, env: Mapping[str, str], namespace: Path, private: Path, point: str, marker: Path, release: Path):
    return process_starter(
        [TOOL, "--namespace", namespace, "--private-repo", private],
        env=environment(
            env,
            PLATFORM_PKI_INVENTORY_INSTALL_PAUSE_AT=point,
            PLATFORM_PKI_INVENTORY_INSTALL_PAUSE_MARKER=os.fspath(marker),
            PLATFORM_PKI_INVENTORY_INSTALL_PAUSE_RELEASE=os.fspath(release),
        ),
        timeout=30,
    )


def exchange_supported(tmp_path: Path, process_runner, env) -> bool:
    first = tmp_path / "exchange-a"
    second = tmp_path / "exchange-b"
    first.touch()
    second.touch()
    result = process_runner(["mv", "--exchange", "--no-copy", "-T", "--", first, second], env=env, timeout=10)
    first.unlink(missing_ok=True)
    second.unlink(missing_ok=True)
    return result.status == 0


def test_frozen_oracle_and_common_library_match_recorded_provenance() -> None:
    plan = (REPOSITORY / "docs/plans/platform-pki-python-migration.md").read_text(
        encoding="utf-8"
    )
    assert hashlib.sha256(ORACLE.read_bytes()).hexdigest() == ORACLE_SHA256
    assert hashlib.sha256(
        (REPOSITORY / "lib/platform-pki-common.sh").read_bytes()
    ).hexdigest() == COMMON_SHA256
    assert ORACLE_COMMIT in plan
    assert os.access(ORACLE, os.X_OK)


def test_inventory_install_compatibility_help_matches_oracle(
    process_runner, isolated_environment
) -> None:
    oracle = process_runner([ORACLE, "--help"], env=isolated_environment, timeout=30)
    result = process_runner([TOOL, "--help"], env=isolated_environment, timeout=30)
    assert result == ProcessResult(result.args, 0, oracle.stdout, "")


@pytest.mark.parametrize("tool", INTERFACES)
def test_inventory_install_three_interfaces_install_noop_and_normalize(
    tmp_path, process_runner, isolated_environment, tool
) -> None:
    namespace = tmp_path / tool[0].name
    result = process_runner(
        [INIT, "--namespace", namespace], env=isolated_environment, timeout=30
    )
    assert_result(result, 0)
    private = tmp_path / f"private-{tool[0].name}"
    (private / "pki").mkdir(mode=0o700, parents=True)
    private.chmod(0o700)
    write_private(private / "pki/services.yml", INVENTORY)
    destination = namespace / "pki/inventory/services.yml"

    result = run_interface(
        process_runner, isolated_environment, tool, namespace, private
    )
    assert_result(
        result,
        0,
        stdout=f"[OK] Inventory installed: {destination}\n",
        stderr="",
    )
    inode = destination.stat().st_ino

    result = run_interface(
        process_runner, isolated_environment, tool, namespace, private
    )
    assert_result(
        result,
        0,
        stdout=f"[OK] Inventory already current: {destination}\n",
        stderr="",
    )
    assert destination.stat().st_ino == inode

    destination.chmod(0o400)
    result = run_interface(
        process_runner, isolated_environment, tool, namespace, private
    )
    assert_result(
        result,
        0,
        stdout=f"[OK] Inventory normalized: {destination}\n",
        stderr="",
    )
    assert mode(destination) == 0o600


def test_inventory_install_initial_noop_and_mode_normalization(tmp_path, process_runner, isolated_environment) -> None:
    namespace, pki, private = setup_workspace(tmp_path, process_runner, isolated_environment)
    destination = pki / "inventory/services.yml"
    result = run(process_runner, isolated_environment, namespace, private)
    assert_result(result, 0)
    assert "Inventory installed:" in result.stdout
    assert destination.read_bytes() == (private / "pki/services.yml").read_bytes()
    assert mode(destination) == 0o600

    inode = destination.stat().st_ino
    result = run(process_runner, isolated_environment, namespace, private)
    assert_result(result, 0)
    assert "Inventory already current:" in result.stdout
    assert destination.stat().st_ino == inode

    destination.chmod(0o400)
    result = run(process_runner, isolated_environment, namespace, private)
    assert_result(result, 0)
    assert "Inventory normalized:" in result.stdout
    assert mode(destination) == 0o600


def test_inventory_install_prepares_missing_legacy_control_state(tmp_path, process_runner, isolated_environment) -> None:
    namespace, pki, private = setup_workspace(tmp_path, process_runner, isolated_environment)
    shutil.rmtree(pki / "state")
    shutil.rmtree(pki / "locks")
    (pki / "root-ca").mkdir(mode=0o700)
    (pki / "intermediate-ca").mkdir(mode=0o700)

    result = run(process_runner, isolated_environment, namespace, private)

    assert_result(result, 0)
    assert (pki / "inventory/services.yml").read_bytes() == (private / "pki/services.yml").read_bytes()
    for directory in ("locks", "state", "state/rollover", "state/rollovers", "state/generation-reservations"):
        path = pki / directory
        assert path.is_dir() and mode(path) == 0o700
    assert {path.name for path in (pki / "locks").iterdir()} == {"lifecycle", "root", "intermediate", "inventory"}
    assert all(mode(path) == 0o600 for path in (pki / "locks").iterdir())


def test_inventory_install_source_identity_race_preserves_destination(tmp_path, process_runner, process_starter, isolated_environment) -> None:
    namespace, pki, private = setup_workspace(tmp_path, process_runner, isolated_environment)
    assert_result(run(process_runner, isolated_environment, namespace, private), 0)
    destination = pki / "inventory/services.yml"
    before = digest(destination)
    target = tmp_path / "race-target"
    target.write_text("not inventory\n")
    source = private / "pki/services.yml"
    marker = tmp_path / "source-race-triggered"
    release = tmp_path / "source-race-release"
    process = start_paused(
        process_starter, isolated_environment, namespace, private,
        "inventory-source-before-read", marker, release,
    )
    wait_for_path(marker)
    source.unlink()
    source.symlink_to(target)
    release.touch()
    result = process.wait()
    assert result.status == 1
    assert marker.is_file()
    assert source.is_symlink()
    assert source.readlink() == target
    assert digest(destination) == before


def test_inventory_install_destination_parent_replacement_preserves_original_and_does_not_publish(tmp_path, process_runner, process_starter, isolated_environment) -> None:
    namespace, pki, private = setup_workspace(tmp_path, process_runner, isolated_environment)
    assert_result(run(process_runner, isolated_environment, namespace, private), 0)
    inventory = pki / "inventory"
    destination = inventory / "services.yml"
    before = digest(destination)
    write_private(private / "pki/services.yml", UPDATED_INVENTORY)
    old_inventory = tmp_path / "validated-inventory"
    marker = tmp_path / "parent-race-triggered"
    release = tmp_path / "parent-race-release"
    process = start_paused(
        process_starter, isolated_environment, namespace, private,
        "stage-before-create", marker, release,
    )
    wait_for_path(marker)
    inventory.rename(old_inventory)
    inventory.mkdir(mode=0o700)
    release.touch()
    result = process.wait()

    assert result.status == 1
    assert marker.is_file()
    assert inventory.is_dir() and old_inventory.is_dir()
    assert inventory.stat().st_ino != old_inventory.stat().st_ino
    assert digest(old_inventory / "services.yml") == before
    assert not (inventory / "services.yml").exists()
    assert not list(inventory.glob(".platform-pki-inventory-install.*"))
    assert not list(old_inventory.glob(".platform-pki-inventory-install.*"))


def test_inventory_install_publication_identity_race_preserves_foreign_destination(tmp_path, process_runner, process_starter, isolated_environment) -> None:
    if not exchange_supported(tmp_path, process_runner, isolated_environment):
        pytest.skip("mv --exchange --no-copy is unavailable")
    namespace, pki, private = setup_workspace(tmp_path, process_runner, isolated_environment)
    assert_result(run(process_runner, isolated_environment, namespace, private), 0)
    destination = pki / "inventory/services.yml"
    before = digest(destination)
    write_private(private / "pki/services.yml", UPDATED_INVENTORY)
    saved = tmp_path / "raced-original.yml"
    marker = tmp_path / "publication-race-triggered"
    release = tmp_path / "publication-race-release"
    process = start_paused(
        process_starter, isolated_environment, namespace, private,
        "guarded-exchange-before-mutation", marker, release,
    )
    wait_for_path(marker)
    destination.rename(saved)
    destination.write_text("foreign inventory\n")
    destination.chmod(0o600)
    release.touch()
    result = process.wait()
    assert result.status == 1
    assert marker.is_file()
    assert destination.read_text() == "foreign inventory\n"
    assert digest(saved) == before


def test_inventory_install_post_exchange_failure_retains_recovery_guard(tmp_path, process_runner, process_starter, isolated_environment) -> None:
    if not exchange_supported(tmp_path, process_runner, isolated_environment):
        pytest.skip("mv --exchange --no-copy is unavailable")
    namespace, pki, private = setup_workspace(tmp_path, process_runner, isolated_environment)
    assert_result(run(process_runner, isolated_environment, namespace, private), 0)
    destination = pki / "inventory/services.yml"
    before = digest(destination)
    write_private(private / "pki/services.yml", UPDATED_INVENTORY)
    marker = tmp_path / "post-exchange-race-triggered"
    release = tmp_path / "post-exchange-race-release"
    process = start_paused(
        process_starter, isolated_environment, namespace, private,
        "guarded-exchange-after-mutation", marker, release,
    )
    wait_for_path(marker)
    stages = list((pki / "inventory").glob(".platform-pki-inventory-install.*"))
    assert len(stages) == 1
    stages[0].unlink()
    release.touch()
    result = process.wait()
    assert result.status == 1
    assert marker.is_file()
    assert "requires recovery; retained artifacts under:" in result.stderr
    assert all((pki / "locks" / name).is_file() for name in ("root", "intermediate", "inventory"))
    guards = list((pki / "inventory").glob(".platform-pki-inventory-guard.*.link"))
    assert len(guards) == 1
    assert digest(guards[0]) == before


def test_inventory_install_forced_rename_fallback_has_safe_metadata(tmp_path, process_runner, isolated_environment) -> None:
    namespace, pki, private = setup_workspace(tmp_path, process_runner, isolated_environment)
    write_private(private / "pki/services.yml", UPDATED_INVENTORY)
    result = run(process_runner, environment(isolated_environment, PLATFORM_PKI_FORCE_RENAME_FALLBACK="1"), namespace, private)
    assert_result(result, 0)
    destination = pki / "inventory/services.yml"
    assert "days: 2" in destination.read_text()
    metadata = destination.stat()
    assert mode(destination) == 0o600
    assert metadata.st_uid == os.getuid()
    assert metadata.st_nlink == 1


@pytest.mark.parametrize("source_kind", ["invalid", "symlink", "hardlink", "writable"])
def test_inventory_install_rejects_unsafe_sources_without_changing_destination(tmp_path, process_runner, isolated_environment, source_kind) -> None:
    namespace, pki, private = setup_workspace(tmp_path, process_runner, isolated_environment)
    assert_result(run(process_runner, isolated_environment, namespace, private), 0)
    destination = pki / "inventory/services.yml"
    source = private / "pki/services.yml"
    before = digest(destination)
    if source_kind == "invalid":
        write_private(source, "services: {}\n")
    elif source_kind == "symlink":
        source.unlink()
        source.symlink_to(destination)
    elif source_kind == "hardlink":
        os.link(source, private / "pki/services.link")
    else:
        source.chmod(0o622)
    result = run(process_runner, isolated_environment, namespace, private)
    assert result.status == 1
    assert digest(destination) == before


def test_inventory_install_rejects_unsafe_destination_and_directory(tmp_path, process_runner, isolated_environment) -> None:
    namespace, pki, private = setup_workspace(tmp_path, process_runner, isolated_environment)
    assert_result(run(process_runner, isolated_environment, namespace, private), 0)
    destination = pki / "inventory/services.yml"
    real = destination.with_name("services.real")
    destination.rename(real)
    destination.symlink_to(real)
    result = run(process_runner, isolated_environment, namespace, private)
    assert result.status == 1
    assert destination.is_symlink()
    destination.unlink()
    real.rename(destination)

    inventory = pki / "inventory"
    inventory.chmod(0o777)
    result = run(process_runner, isolated_environment, namespace, private)
    assert result.status == 1
    assert mode(inventory) == 0o777


def test_inventory_install_default_private_repository(tmp_path, process_runner, isolated_environment) -> None:
    namespace, _, private = setup_workspace(tmp_path, process_runner, isolated_environment)
    root = tmp_path / "default"
    checkout = root / "platform-tools"
    default_private = root / "platform-private/pki"
    checkout.mkdir(parents=True, mode=0o700)
    default_private.mkdir(parents=True, mode=0o700)
    root.chmod(0o700)
    shutil.copyfile(private / "pki/services.yml", default_private / "services.yml")
    default_private.parent.chmod(0o700)
    (default_private / "services.yml").chmod(0o600)
    result = run(process_runner, isolated_environment, namespace, None, cwd=checkout)
    assert_result(result, 0)


def test_inventory_install_rejects_private_repo_conflicts_and_duplicate_option(tmp_path, process_runner, isolated_environment) -> None:
    namespace, pki, private = setup_workspace(tmp_path, process_runner, isolated_environment)
    assert run(process_runner, isolated_environment, namespace, pki).status == 1
    assert process_runner([TOOL, "--namespace", namespace, "--private-repo", ""], env=isolated_environment, timeout=30).status == 1
    assert process_runner([TOOL, "--namespace", namespace, "--private-repo", private, "--private-repo", private], env=isolated_environment, timeout=30).status == 1


def _normalize_case_root(root: Path, output: str) -> str:
    return output.replace(os.fspath(root), "<CASE>")


def _differential_seed(
    tmp_path: Path,
    process_runner,
    isolated_environment: Mapping[str, str],
    *,
    installed: bool = False,
) -> Path:
    seed = tmp_path / "seed"
    seed.mkdir(mode=0o700)
    namespace = seed / "namespace"
    result = process_runner(
        [INIT, "--namespace", namespace], env=isolated_environment, timeout=30
    )
    assert_result(result, 0)
    private = seed / "private"
    (private / "pki").mkdir(mode=0o700, parents=True)
    private.chmod(0o700)
    write_private(private / "pki/services.yml", INVENTORY)
    if installed:
        result = run_interface(
            process_runner,
            isolated_environment,
            (ORACLE,),
            namespace,
            private,
        )
        assert_result(result, 0)
    return seed


def _run_inventory_differential(
    seed: Path,
    case_root: Path,
    isolated_environment: Mapping[str, str],
    *,
    private_relative: Path | None = Path("private"),
    extra_environment: Mapping[str, str] | None = None,
    cwd_relative: Path = Path("."),
    runner=run_process,
):
    base_environment = environment(
        isolated_environment,
        PLATFORM_TOOLS_LIB_DIR=os.fspath(REPOSITORY / "lib"),
    )
    if extra_environment is not None:
        base_environment.update(extra_environment)

    def command(root: Path, tool: tuple[Path | str, ...]) -> tuple[Path | str, ...]:
        arguments: list[Path | str] = [
            *tool,
            "--namespace",
            root / "namespace",
        ]
        if private_relative is not None:
            arguments.extend(("--private-repo", root / private_relative))
        return tuple(arguments)

    return run_differential_case(
        seed,
        case_root,
        Path("namespace/pki"),
        lambda root: command(root, (ORACLE,)),
        lambda root: command(root, (UNIFIED, "inventory-install")),
        base_environment,
        output_normalizers=(_normalize_case_root,),
        runner=runner,
        run_options={"timeout": 30},
        cwd_relative=cwd_relative,
    )


def test_bash_python_fresh_inventory_install_is_equivalent(
    tmp_path, process_runner, isolated_environment
) -> None:
    seed = _differential_seed(tmp_path, process_runner, isolated_environment)
    result = _run_inventory_differential(
        seed, tmp_path / "fresh-case", isolated_environment
    )
    result.assert_equivalent()


def test_bash_python_noop_and_mode_normalization_are_equivalent(
    tmp_path, process_runner, isolated_environment
) -> None:
    seed = _differential_seed(
        tmp_path, process_runner, isolated_environment, installed=True
    )
    noop = _run_inventory_differential(
        seed, tmp_path / "noop-case", isolated_environment
    )
    noop.assert_equivalent()

    (seed / "namespace/pki/inventory/services.yml").chmod(0o400)
    normalized = _run_inventory_differential(
        seed, tmp_path / "normalized-case", isolated_environment
    )
    normalized.assert_equivalent()


def test_bash_python_invalid_inventory_rejection_is_equivalent(
    tmp_path, process_runner, isolated_environment
) -> None:
    seed = _differential_seed(
        tmp_path, process_runner, isolated_environment, installed=True
    )
    write_private(seed / "private/pki/services.yml", "services: {}\n")
    result = _run_inventory_differential(
        seed, tmp_path / "invalid-case", isolated_environment
    )
    result.assert_equivalent()


def test_bash_python_default_private_repository_is_equivalent(
    tmp_path, process_runner, isolated_environment
) -> None:
    seed = _differential_seed(tmp_path, process_runner, isolated_environment)
    (seed / "private").rename(seed / "platform-private")
    (seed / "platform-tools").mkdir(mode=0o700)

    result = _run_inventory_differential(
        seed,
        tmp_path / "default-private-case",
        isolated_environment,
        private_relative=None,
        cwd_relative=Path("platform-tools"),
        extra_environment={"PWD": "/nonexistent/logical-checkout"},
    )

    result.assert_equivalent()


def test_bash_python_legacy_preparation_and_recovery_gate_are_equivalent(
    tmp_path, process_runner, isolated_environment
) -> None:
    legacy_seed = _differential_seed(
        tmp_path, process_runner, isolated_environment
    )
    pki = legacy_seed / "namespace/pki"
    shutil.rmtree(pki / "state")
    shutil.rmtree(pki / "locks")
    (pki / "root-ca").mkdir(mode=0o700)
    (pki / "intermediate-ca").mkdir(mode=0o700)

    legacy = _run_inventory_differential(
        legacy_seed,
        tmp_path / "legacy-preparation-case",
        isolated_environment,
    )
    legacy.assert_equivalent()

    recovery_seed_root = tmp_path / "recovery-seed-root"
    recovery_seed_root.mkdir(mode=0o700)
    recovery_seed = _differential_seed(
        recovery_seed_root, process_runner, isolated_environment
    )
    marker = recovery_seed / "namespace/pki/state/rollover/recovery-required"
    write_private(marker, "transaction=inventory-install-test\n")

    recovery = _run_inventory_differential(
        recovery_seed,
        tmp_path / "recovery-gate-case",
        isolated_environment,
    )
    recovery.assert_equivalent()


@pytest.mark.parametrize("forced_fallback", [False, True], ids=["exchange", "fallback"])
def test_bash_python_existing_destination_replacement_is_equivalent(
    tmp_path, process_runner, isolated_environment, forced_fallback
) -> None:
    seed = _differential_seed(
        tmp_path, process_runner, isolated_environment, installed=True
    )
    write_private(seed / "private/pki/services.yml", UPDATED_INVENTORY)
    extra_environment = (
        {"PLATFORM_PKI_FORCE_RENAME_FALLBACK": "1"}
        if forced_fallback
        else None
    )

    result = _run_inventory_differential(
        seed,
        tmp_path / f"replacement-{forced_fallback}-case",
        isolated_environment,
        extra_environment=extra_environment,
    )

    result.assert_equivalent()


def test_bash_python_overlap_rejection_is_equivalent(
    tmp_path, process_runner, isolated_environment
) -> None:
    seed = _differential_seed(tmp_path, process_runner, isolated_environment)
    private = seed / "namespace/pki/private-repository"
    (private / "pki").mkdir(mode=0o700, parents=True)
    private.chmod(0o700)
    write_private(private / "pki/services.yml", INVENTORY)

    result = _run_inventory_differential(
        seed,
        tmp_path / "overlap-case",
        isolated_environment,
        private_relative=Path("namespace/pki/private-repository"),
    )

    result.assert_equivalent()


def test_bash_python_root_lock_contention_is_equivalent(
    tmp_path, process_runner, isolated_environment
) -> None:
    seed = _differential_seed(tmp_path, process_runner, isolated_environment)
    write_private(seed / "namespace/pki/locks/root", "")

    def contended_runner(arguments, **options):
        lock_path = Path(options["cwd"]) / "namespace/pki/locks/root"
        with lock_path.open("r+b") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return run_process(arguments, **options)

    result = _run_inventory_differential(
        seed,
        tmp_path / "root-contention-case",
        isolated_environment,
        runner=contended_runner,
    )

    result.assert_equivalent()
