from __future__ import annotations

import os
import shutil
from collections.abc import Callable, Mapping
from pathlib import Path

import pytest

from ..harness import ProcessResult
from .support import BIN, assert_result, digest, environment, executable, executable_directory, mode, write_executable, write_private


pytestmark = pytest.mark.pki
INIT = BIN / "platform-pki-init"
TOOL = BIN / "platform-pki-inventory-install"
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


def setup_workspace(tmp_path: Path, process_runner, env) -> tuple[Path, Path, Path]:
    namespace = tmp_path / "namespace"
    result = process_runner([INIT, "--namespace", namespace], env=env, timeout=30)
    assert_result(result, 0)
    private = tmp_path / "platform-private"
    private.mkdir(mode=0o700)
    (private / "pki").mkdir(mode=0o700)
    write_private(private / "pki/services.yml", INVENTORY)
    return namespace, namespace / "pki", private


def race_environment(path: Path) -> None:
    write_private(path, """if [[ ${RACE_MODE:-} == source ]]; then
  cp() {
    : >"$RACE_MARKER"
    "$REAL_RM" -f -- "$RACE_SOURCE"
    "$REAL_LN" -s -- "$RACE_TARGET" "$RACE_SOURCE"
    "$REAL_CP" "$@"
  }
elif [[ ${RACE_MODE:-} == publication ]]; then
  mv() {
    if [[ $* == *'--exchange'* && ${RACE_TRIGGERED:-false} == false ]]; then
      RACE_TRIGGERED=true
      : >"$RACE_MARKER"
      "$REAL_MV" -T -- "$RACE_DESTINATION" "$RACE_SAVED_DESTINATION"
      printf '%s\\n' 'foreign inventory' >"$RACE_DESTINATION"
      chmod 600 "$RACE_DESTINATION"
    fi
    "$REAL_MV" "$@"
  }
elif [[ ${RACE_MODE:-} == post_exchange ]]; then
  mv() {
    "$REAL_MV" "$@"
    if [[ $* == *'--exchange'* && ${RACE_TRIGGERED:-false} == false ]]; then
      RACE_TRIGGERED=true
      : >"$RACE_MARKER"
      local exchanged_source=${@: -2:1}
      "$REAL_RM" -f -- "$exchanged_source"
    fi
  }
fi
""")


def exchange_supported(tmp_path: Path, process_runner, env) -> bool:
    first = tmp_path / "exchange-a"
    second = tmp_path / "exchange-b"
    first.touch()
    second.touch()
    result = process_runner(["mv", "--exchange", "--no-copy", "-T", "--", first, second], env=env, timeout=10)
    first.unlink(missing_ok=True)
    second.unlink(missing_ok=True)
    return result.status == 0


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


def test_inventory_install_source_identity_race_preserves_destination(tmp_path, process_runner, isolated_environment) -> None:
    namespace, pki, private = setup_workspace(tmp_path, process_runner, isolated_environment)
    assert_result(run(process_runner, isolated_environment, namespace, private), 0)
    destination = pki / "inventory/services.yml"
    before = digest(destination)
    target = tmp_path / "race-target"
    target.write_text("not inventory\n")
    race_env = tmp_path / "race-env.sh"
    race_environment(race_env)
    source = private / "pki/services.yml"
    marker = tmp_path / "source-race-triggered"
    result = run(
        process_runner,
        environment(
            isolated_environment,
            BASH_ENV=os.fspath(race_env), RACE_MODE="source", REAL_CP=executable("cp"),
            REAL_RM=executable("rm"), REAL_LN=executable("ln"), RACE_SOURCE=os.fspath(source),
            RACE_TARGET=os.fspath(target), RACE_MARKER=os.fspath(marker),
        ),
        namespace, private,
    )
    assert result.status == 1
    assert marker.is_file()
    assert source.is_symlink()
    assert source.readlink() == target
    assert digest(destination) == before


def test_inventory_install_destination_parent_replacement_preserves_original_and_does_not_publish(tmp_path, process_runner, isolated_environment, executable_directory) -> None:
    namespace, pki, private = setup_workspace(tmp_path, process_runner, isolated_environment)
    assert_result(run(process_runner, isolated_environment, namespace, private), 0)
    inventory = pki / "inventory"
    destination = inventory / "services.yml"
    before = digest(destination)
    write_private(private / "pki/services.yml", UPDATED_INVENTORY)
    old_inventory = tmp_path / "validated-inventory"
    marker = tmp_path / "parent-race-triggered"
    fake_bin = executable_directory / "parent-race-bin"
    write_executable(fake_bin / "mktemp", """#!/usr/bin/env bash
set -euo pipefail
if [[ $1 == /proc/self/fd/*/.platform-pki-exchange-a.* && ! -e $RACE_MARKER ]]; then
  "$REAL_MV" -- "$RACE_PARENT" "$RACE_OLD_PARENT"
  "$REAL_MKDIR" -m 700 -- "$RACE_PARENT"
  : >"$RACE_MARKER"
fi
exec "$REAL_MKTEMP" "$@"
""")

    result = run(
        process_runner,
        environment(
            isolated_environment,
            PATH=f"{fake_bin}:{isolated_environment['PATH']}",
            RACE_MARKER=os.fspath(marker),
            RACE_PARENT=os.fspath(inventory),
            RACE_OLD_PARENT=os.fspath(old_inventory),
            REAL_MKDIR=executable("mkdir"),
            REAL_MKTEMP=executable("mktemp"),
            REAL_MV=executable("mv"),
        ),
        namespace,
        private,
    )

    assert result.status == 1
    assert marker.is_file()
    assert inventory.is_dir() and old_inventory.is_dir()
    assert inventory.stat().st_ino != old_inventory.stat().st_ino
    assert digest(old_inventory / "services.yml") == before
    assert not (inventory / "services.yml").exists()
    assert not list(inventory.glob(".platform-pki-inventory-install.*"))
    assert not list(old_inventory.glob(".platform-pki-inventory-install.*"))


def test_inventory_install_publication_identity_race_preserves_foreign_destination(tmp_path, process_runner, isolated_environment) -> None:
    if not exchange_supported(tmp_path, process_runner, isolated_environment):
        pytest.skip("mv --exchange --no-copy is unavailable")
    namespace, pki, private = setup_workspace(tmp_path, process_runner, isolated_environment)
    assert_result(run(process_runner, isolated_environment, namespace, private), 0)
    destination = pki / "inventory/services.yml"
    before = digest(destination)
    write_private(private / "pki/services.yml", UPDATED_INVENTORY)
    race_env = tmp_path / "race-env.sh"
    race_environment(race_env)
    saved = tmp_path / "raced-original.yml"
    marker = tmp_path / "publication-race-triggered"
    result = run(
        process_runner,
        environment(isolated_environment, BASH_ENV=os.fspath(race_env), RACE_MODE="publication", RACE_MARKER=os.fspath(marker), REAL_MV=executable("mv"), RACE_DESTINATION=os.fspath(destination), RACE_SAVED_DESTINATION=os.fspath(saved)),
        namespace, private,
    )
    assert result.status == 1
    assert marker.is_file()
    assert destination.read_text() == "foreign inventory\n"
    assert digest(saved) == before


def test_inventory_install_post_exchange_failure_retains_recovery_guard(tmp_path, process_runner, isolated_environment) -> None:
    if not exchange_supported(tmp_path, process_runner, isolated_environment):
        pytest.skip("mv --exchange --no-copy is unavailable")
    namespace, pki, private = setup_workspace(tmp_path, process_runner, isolated_environment)
    assert_result(run(process_runner, isolated_environment, namespace, private), 0)
    destination = pki / "inventory/services.yml"
    before = digest(destination)
    write_private(private / "pki/services.yml", UPDATED_INVENTORY)
    race_env = tmp_path / "race-env.sh"
    race_environment(race_env)
    marker = tmp_path / "post-exchange-race-triggered"
    result = run(
        process_runner,
        environment(isolated_environment, BASH_ENV=os.fspath(race_env), RACE_MODE="post_exchange", RACE_MARKER=os.fspath(marker), REAL_MV=executable("mv"), REAL_RM=executable("rm")),
        namespace, private,
    )
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
