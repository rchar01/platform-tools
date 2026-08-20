from __future__ import annotations

import json
import os
from collections.abc import Callable, Mapping
from pathlib import Path

import pytest

import src.platform_pki.offline_workspace as offline_workspace_module
from src.platform_pki.errors import ApplicationError
from src.platform_pki.parser import parse_route

from ..harness import ProcessResult
from .support import BIN, assert_result, mode


pytestmark = pytest.mark.pki
TOOL = (BIN / "platform-pki", "offline-workspace", "init")
RELATIVE_DIRECTORIES = (
    "",
    "media-in",
    "media-in/request",
    "media-in/signer-input",
    "media-in/evidence",
    "work",
    "work/approved",
    "media-out",
    "media-out/approval",
    "media-out/response",
    "media-out/outcome",
)
PAYLOAD_ROOTS = (
    "media-in/request",
    "media-in/signer-input",
    "media-in/evidence",
    "work/approved",
    "media-out/approval",
    "media-out/response",
    "media-out/outcome",
)


def run(
    process_runner: Callable[..., ProcessResult],
    environment: Mapping[str, str],
    service: str = "registry-dev",
    *arguments: object,
) -> ProcessResult:
    return process_runner([*TOOL, service, *arguments], env=environment, timeout=30)


def expected_directories(workspace: Path) -> list[str]:
    return [
        os.fspath(workspace if not relative else workspace / relative)
        for relative in RELATIVE_DIRECTORIES
    ]


def tree_identity(workspace: Path) -> dict[str, tuple[int, int, int, int, int]]:
    return {
        path.relative_to(workspace).as_posix() or ".": (
            path.lstat().st_dev,
            path.lstat().st_ino,
            path.lstat().st_mode,
            path.lstat().st_mtime_ns,
            path.lstat().st_ctime_ns,
        )
        for path in (workspace, *sorted(workspace.rglob("*")))
    }


def assert_exact_skeleton(workspace: Path) -> None:
    directories = tuple(
        workspace if not relative else workspace / relative
        for relative in RELATIVE_DIRECTORIES
    )
    assert all(path.is_dir() and not path.is_symlink() and mode(path) == 0o700 for path in directories)
    metadata = workspace / "README.md"
    assert metadata.is_file() and not metadata.is_symlink() and mode(metadata) == 0o600
    assert "custody and staging" in metadata.read_text(encoding="ascii")
    assert "authoritative signer" in metadata.read_text(encoding="ascii")
    relative_entries = {
        path.relative_to(workspace).as_posix() for path in workspace.rglob("*")
    }
    assert relative_entries == {
        "README.md",
        *(relative for relative in RELATIVE_DIRECTORIES if relative),
    }
    assert not any(
        token in path.name.lower()
        for path in workspace.rglob("*")
        for token in (".key", "public-key", "transaction", "protocol", "recovery")
    )


def test_default_root_prefers_xdg_and_emits_fixed_json(
    process_runner,
    isolated_environment,
) -> None:
    root = Path(isolated_environment["XDG_CONFIG_HOME"]) / "platform-pki-offline"
    workspace = root / "registry-dev"
    xdg_environment = dict(isolated_environment)
    xdg_environment.pop("HOME")

    result = run(process_runner, xdg_environment)

    assert_result(result, 0, stderr="")
    parsed = json.loads(result.stdout)
    assert list(parsed) == [
        "status",
        "service",
        "root",
        "workspace_dir",
        "authoritative_pki_default",
        "directories",
    ]
    assert parsed == {
        "status": "created",
        "service": "registry-dev",
        "root": os.fspath(root),
        "workspace_dir": os.fspath(workspace),
        "authoritative_pki_default": os.fspath(
            Path(isolated_environment["XDG_CONFIG_HOME"])
            / "platform-infrastructure/pki"
        ),
        "directories": expected_directories(workspace),
    }
    assert_exact_skeleton(workspace)


def test_default_root_falls_back_to_home_and_root_override_wins(
    tmp_path,
    process_runner,
    isolated_environment,
) -> None:
    fallback_environment = dict(isolated_environment)
    fallback_environment.pop("XDG_CONFIG_HOME")
    home_root = Path(fallback_environment["HOME"]) / ".config/platform-pki-offline"

    fallback = run(process_runner, fallback_environment, "home-service")

    assert_result(fallback, 0, stderr="")
    assert json.loads(fallback.stdout)["root"] == os.fspath(home_root)
    assert_exact_skeleton(home_root / "home-service")

    override_root = tmp_path / "explicit/offline"
    override = run(
        process_runner,
        isolated_environment,
        "override-service",
        "--root",
        override_root,
    )

    assert_result(override, 0, stderr="")
    parsed = json.loads(override.stdout)
    assert parsed["root"] == os.fspath(override_root)
    assert parsed["authoritative_pki_default"] == os.fspath(
        Path(isolated_environment["XDG_CONFIG_HOME"])
        / "platform-infrastructure/pki"
    )
    assert_exact_skeleton(override_root / "override-service")


def test_explicit_root_without_configuration_home_reports_null_default(
    tmp_path,
    process_runner,
    isolated_environment,
) -> None:
    root = tmp_path / "explicit-no-config"
    environment = {
        key: value
        for key, value in isolated_environment.items()
        if key not in {"HOME", "XDG_CONFIG_HOME"}
    }

    result = run(
        process_runner,
        environment,
        "no-config-service",
        "--root",
        root,
    )

    assert_result(result, 0, stderr="")
    parsed = json.loads(result.stdout)
    assert list(parsed) == [
        "status",
        "service",
        "root",
        "workspace_dir",
        "authoritative_pki_default",
        "directories",
    ]
    assert parsed["authoritative_pki_default"] is None
    assert_exact_skeleton(root / "no-config-service")


def test_default_root_requires_configuration_home(
    process_runner,
    isolated_environment,
) -> None:
    environment = {
        key: value
        for key, value in isolated_environment.items()
        if key not in {"HOME", "XDG_CONFIG_HOME"}
    }

    result = run(process_runner, environment)

    assert_result(result, 1, stdout="")
    assert result.stderr == (
        "[ERROR] HOME or XDG_CONFIG_HOME is required when --root is absent\n"
    )


def test_exact_rerun_is_existing_and_changes_nothing(
    tmp_path,
    process_runner,
    isolated_environment,
) -> None:
    root = tmp_path / "offline"
    workspace = root / "registry-dev"
    created = run(process_runner, isolated_environment, "registry-dev", "--root", root)
    assert_result(created, 0, stderr="")
    before = tree_identity(workspace)

    existing = run(process_runner, isolated_environment, "registry-dev", "--root", root)

    assert_result(existing, 0, stderr="")
    assert json.loads(existing.stdout) == {
        **json.loads(created.stdout),
        "status": "existing",
    }
    assert tree_identity(workspace) == before


@pytest.mark.parametrize("payload_root", PAYLOAD_ROOTS)
def test_rerun_treats_leaf_payload_contents_as_opaque_workflow_state(
    payload_root,
    tmp_path,
    process_runner,
    isolated_environment,
) -> None:
    root = tmp_path / "offline"
    workspace = root / "registry-dev"
    assert_result(
        run(process_runner, isolated_environment, "registry-dev", "--root", root),
        0,
    )
    payload = workspace / payload_root
    opaque = payload / "operator-owned"
    opaque.mkdir(mode=0o700)
    opaque.chmod(0o000)
    regular = payload / "payload.bin"
    regular.write_bytes(b"operator payload\n")
    regular.chmod(0o644)
    dangling = payload / "payload-link"
    dangling.symlink_to("missing-operator-target")

    result = run(process_runner, isolated_environment, "registry-dev", "--root", root)

    assert_result(result, 0, stderr="")
    assert json.loads(result.stdout)["status"] == "existing"
    assert mode(opaque) == 0o000
    opaque.chmod(0o700)
    assert regular.read_bytes() == b"operator payload\n"
    assert dangling.is_symlink() and dangling.readlink() == Path(
        "missing-operator-target"
    )


def test_safe_partial_tree_is_completed_without_replacing_existing_nodes(
    tmp_path,
    process_runner,
    isolated_environment,
) -> None:
    root = tmp_path / "offline"
    workspace = root / "registry-dev"
    assert_result(
        run(process_runner, isolated_environment, "registry-dev", "--root", root),
        0,
    )
    retained = workspace / "media-in/request"
    retained_identity = tree_identity(workspace)["media-in/request"]
    (workspace / "README.md").unlink()
    (workspace / "work/approved").rmdir()
    (workspace / "media-out/outcome").rmdir()

    completed = run(process_runner, isolated_environment, "registry-dev", "--root", root)

    assert_result(completed, 0, stderr="")
    assert json.loads(completed.stdout)["status"] == "created"
    assert tree_identity(workspace)["media-in/request"] == retained_identity
    assert retained.is_dir()
    assert_exact_skeleton(workspace)


@pytest.mark.parametrize(
    "root",
    ("relative", "/", "/tmp/trailing/", "/tmp//empty", "/tmp/dot/../parent"),
)
def test_rejects_relative_root_and_noncanonical_absolute_roots(
    root,
    process_runner,
    isolated_environment,
) -> None:
    result = run(process_runner, isolated_environment, "registry-dev", "--root", root)

    assert_result(result, 1, stdout="")
    assert "Offline workspace path is invalid" in result.stderr


@pytest.mark.parametrize("relationship", ("equal", "ancestor", "descendant"))
def test_rejects_root_overlap_with_default_authoritative_pki_before_mutation(
    relationship,
    process_runner,
    isolated_environment,
) -> None:
    config_home = Path(isolated_environment["XDG_CONFIG_HOME"])
    authoritative = config_home / "platform-infrastructure/pki"
    roots = {
        "equal": authoritative,
        "ancestor": authoritative.parent,
        "descendant": authoritative / "offline",
    }
    root = roots[relationship]

    result = run(process_runner, isolated_environment, "registry-dev", "--root", root)

    assert_result(result, 1, stdout="")
    assert result.stderr == (
        "[ERROR] Offline workspace root must be disjoint from the authoritative "
        "PKI default\n"
    )
    assert not (root / "registry-dev").exists()


def test_component_prefix_is_not_treated_as_authoritative_overlap(
    process_runner,
    isolated_environment,
) -> None:
    config_home = Path(isolated_environment["XDG_CONFIG_HOME"])
    root = config_home / "platform-infrastructure/pki-offline"

    result = run(process_runner, isolated_environment, "registry-dev", "--root", root)

    assert_result(result, 0, stderr="")
    assert json.loads(result.stdout)["root"] == os.fspath(root)
    assert_exact_skeleton(root / "registry-dev")


@pytest.mark.parametrize("target", ("directory", "metadata"))
def test_rejects_changed_modes_without_repair(
    target,
    tmp_path,
    process_runner,
    isolated_environment,
) -> None:
    root = tmp_path / "offline"
    workspace = root / "registry-dev"
    assert_result(
        run(process_runner, isolated_environment, "registry-dev", "--root", root),
        0,
    )
    changed = workspace / "media-in" if target == "directory" else workspace / "README.md"
    changed.chmod(0o770 if target == "directory" else 0o660)

    result = run(process_runner, isolated_environment, "registry-dev", "--root", root)

    assert_result(result, 1, stdout="")
    assert mode(changed) == (0o770 if target == "directory" else 0o660)


def test_rejects_foreign_owned_root_without_repair(
    tmp_path,
    monkeypatch,
    isolated_environment,
) -> None:
    root = tmp_path / "foreign"
    root.mkdir(mode=0o700)
    original_uid = os.geteuid()
    monkeypatch.setattr(offline_workspace_module.os, "geteuid", lambda: original_uid + 1)
    parsed = parse_route(
        ("offline-workspace", "init"),
        ("registry-dev", "--root", os.fspath(root)),
    )

    with pytest.raises(
        ApplicationError,
        match="ancestor is not trusted|not current-user-owned",
    ):
        offline_workspace_module.initialize_offline_workspace(
            parsed,
            environment=isolated_environment,
        )

    assert not (root / "registry-dev").exists()
    assert mode(root) == 0o700


@pytest.mark.parametrize("collision", ("symlink", "file"))
def test_rejects_symlink_and_non_directory_conflicts(
    collision,
    tmp_path,
    process_runner,
    isolated_environment,
) -> None:
    root = tmp_path / "offline"
    workspace = root / "registry-dev"
    assert_result(
        run(process_runner, isolated_environment, "registry-dev", "--root", root),
        0,
    )
    target = workspace / "media-in/evidence"
    target.rmdir()
    if collision == "symlink":
        victim = tmp_path / "victim"
        victim.mkdir(mode=0o700)
        target.symlink_to(victim, target_is_directory=True)
    else:
        target.write_bytes(b"conflict\n")
        target.chmod(0o600)

    result = run(process_runner, isolated_environment, "registry-dev", "--root", root)

    assert_result(result, 1, stdout="")
    assert target.is_symlink() if collision == "symlink" else target.is_file()


@pytest.mark.parametrize("mutation", ("metadata", "unexpected-structure"))
def test_rejects_changed_metadata_and_unexpected_content(
    mutation,
    tmp_path,
    process_runner,
    isolated_environment,
) -> None:
    root = tmp_path / "offline"
    workspace = root / "registry-dev"
    assert_result(
        run(process_runner, isolated_environment, "registry-dev", "--root", root),
        0,
    )
    if mutation == "metadata":
        changed = workspace / "README.md"
        changed.write_bytes(b"changed metadata\n")
    else:
        changed = workspace / "media-in/unexpected"
        changed.mkdir(mode=0o700)

    result = run(process_runner, isolated_environment, "registry-dev", "--root", root)

    assert_result(result, 1, stdout="")
    assert changed.exists()
