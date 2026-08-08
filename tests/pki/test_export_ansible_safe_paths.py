from __future__ import annotations

import os
import shutil
import hashlib
import time
from collections.abc import Callable, Mapping
from pathlib import Path

import pytest

from ..harness import ProcessResult
from .migration_harness import run_differential_case
from .support import BIN, REPOSITORY, assert_result, environment, executable, executable_directory, mode, write_executable, write_private


pytestmark = pytest.mark.pki
TOOL = BIN / "platform-pki-export-ansible"
ORACLE = REPOSITORY / "tests/pki/oracles/platform-pki-export-ansible/platform-pki-export-ansible"
UNIFIED = BIN / "platform-pki"
ORACLE_COMMIT = "00c7cd55fa51ffc3e5911f0f3bcba1b76e7c5f6b"
ORACLE_SHA256 = "08ea4436e688569ed3a0794b2946ced76a8e69cca335b06cf3fcc4a5577c2599"
COMMON_SHA256 = "dee644be8ab6236cb368a553493f55b53a90c3aead291550f7e635c080a5494f"
SERVICES = ("platform-example", "platform-second")
INVENTORY = """services:
  platform-example:
    common_name: platform-example.internal
    dns:
      - platform-example.internal
  platform-second:
    common_name: platform-second.internal
    dns:
      - platform-second.internal
  platform-host-local:
    key_custody: host-local
    target: host-01
    validation_boundary_sha256: 0000000000000000000000000000000000000000000000000000000000000000
    rollback_hold_seconds: 3600
    common_name: platform-host-local.internal
    dns:
      - platform-host-local.internal
"""


def run(process_runner: Callable[..., ProcessResult], env: Mapping[str, str], *arguments: object, cwd: Path | None = None, tool: Path = TOOL) -> ProcessResult:
    effective = dict(env)
    if tool == ORACLE:
        effective.setdefault("PLATFORM_TOOLS_LIB_DIR", os.fspath(REPOSITORY / "lib"))
    return process_runner([tool, *arguments], env=effective, cwd=cwd, timeout=30)


def wait_for_path(path: Path, timeout: float = 30) -> None:
    deadline = time.monotonic() + timeout
    while not path.exists():
        if time.monotonic() >= deadline:
            pytest.fail(f"timed out waiting for pause marker: {path}", pytrace=False)
        time.sleep(0.01)


def python_environment(env: Mapping[str, str], **values: str) -> dict[str, str]:
    return {**env, **values}


def recovery_entries(parent: Path) -> tuple[Path, ...]:
    return tuple(parent.glob(".*.recovery-*"))


def create_certificates(root: Path, process_runner, env) -> tuple[Path, Path]:
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    root.chmod(0o700)
    key = root / "root.key"
    certificate = root / "root.crt"
    intermediate_key = root / "intermediate.key"
    request = root / "intermediate.csr"
    intermediate = root / "intermediate.crt"
    first = process_runner(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "365", "-subj", "/CN=ExportRoot", "-keyout", key, "-out", certificate], env=env, timeout=30)
    assert_result(first, 0)
    second = process_runner(["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=ExportIntermediate", "-keyout", intermediate_key, "-out", request], env=env, timeout=30)
    assert_result(second, 0)
    third = process_runner(["openssl", "x509", "-req", "-in", request, "-CA", certificate, "-CAkey", key, "-CAcreateserial", "-days", "300", "-out", intermediate], env=env, timeout=30)
    assert_result(third, 0)
    return certificate, intermediate


def create_tree(root: Path, process_runner, env, *, services: tuple[str, ...] = SERVICES) -> Path:
    certificate, intermediate = create_certificates(root, process_runner, env)
    pki = root / "pki"
    for directory in (
        pki / "inventory", pki / "authorities/roots/g1/certs",
        pki / "authorities/intermediates/g1-i1/certs", pki / "locks",
        pki / "state/rollover", pki / "export/ansible",
    ):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    root.chmod(0o700)
    write_private(pki / "inventory/services.yml", INVENTORY if services else "services:\n  missing-service:\n    common_name: missing.internal\n    dns:\n      - missing.internal\n")
    shutil.copyfile(certificate, pki / "authorities/roots/g1/certs/root-ca.crt")
    shutil.copyfile(intermediate, pki / "authorities/intermediates/g1-i1/certs/intermediate-ca.crt")
    write_private(pki / "state/active-issuer", "root=g1\nintermediate=g1-i1\n")
    for service in services:
        service_root = pki / "services" / service
        for directory in (service_root / "private", service_root / "certs", service_root / "chain"):
            directory.mkdir(mode=0o700, parents=True)
        write_private(service_root / "certs/tls.crt", f"{service} certificate\n")
        write_private(service_root / "private/tls.key", f"{service} private key\n")
        write_private(service_root / "chain/ca-chain.crt", f"{service} ca chain\n")
        write_private(service_root / "chain/fullchain.crt", f"{service} full chain\n")
        write_private(service_root / "issuer", "root=g1\nintermediate=g1-i1\n")
    for directory in (pki, *pki.rglob("*")):
        if directory.is_dir():
            directory.chmod(0o700)
    return pki


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


def test_export_compatibility_help_matches_oracle(process_runner, isolated_environment) -> None:
    oracle = run(process_runner, isolated_environment, "--help", tool=ORACLE)
    result = run(process_runner, isolated_environment, "--help")
    assert result == ProcessResult(result.args, 0, oracle.stdout, "")


def test_export_cli_contract_and_literal_service_is_not_evaluated(tmp_path, process_runner, isolated_environment) -> None:
    version = (REPOSITORY / "VERSION").read_text().strip()
    result = run(process_runner, isolated_environment, "--help")
    assert_result(result, 0, stderr="")
    assert "Usage:" in result.stdout
    assert "platform-pki-export-ansible --version | -v" in result.stdout
    assert_result(run(process_runner, isolated_environment, "--version"), 0, stdout=f"platform-pki-export-ansible {version}\n", stderr="")
    literal = f"platform-$(touch {tmp_path / 'eval-injected'})"
    result = run(process_runner, isolated_environment, literal)
    assert result.status == 1
    assert "Invalid service name:" in result.stderr
    assert not (tmp_path / "eval-injected").exists()


def test_export_default_force_modes_content_and_explicit_selection(tmp_path, process_runner, isolated_environment) -> None:
    pki = create_tree(tmp_path / "default", process_runner, isolated_environment)
    stale = pki / "export/ansible/stale.txt"
    stale.write_text("stale export\n")
    assert_result(run(process_runner, isolated_environment, "--pki-dir", pki, "--force"), 0)
    assert not stale.exists()
    export = pki / "export/ansible"
    for directory in (export, export / "ca", export / "services", export / "services/platform-example"):
        assert mode(directory) == 0o700
    assert mode(export / "services/platform-example/tls.key") == 0o600
    assert mode(export / "services/platform-example/tls.crt") == 0o644
    assert (export / "services/platform-example/tls.key").read_text() == "platform-example private key\n"
    assert (export / "services/platform-second/tls.key").is_file()

    selected = pki / "export/selected"
    arguments = (*SERVICES, "--pki-dir", pki, "--export-dir", selected)
    assert_result(run(process_runner, isolated_environment, *arguments), 0)
    assert all((selected / "services" / service / "tls.key").is_file() for service in SERVICES)
    assert_result(run(process_runner, isolated_environment, *arguments, "--force"), 0)


@pytest.mark.parametrize(
    ("destination", "message", "preserved"),
    [
        ("pki", "Export directory must not equal or contain the PKI directory", "inventory/services.yml"),
        ("parent", "Export directory must not equal or contain the PKI directory", "inventory/services.yml"),
        ("services", "Export directory inside the PKI tree must be under its export directory", "services/platform-example/private/tls.key"),
        ("export", "Export directory must be below the PKI export directory", "inventory/services.yml"),
    ],
)
def test_export_rejects_unsafe_replacement_scopes(tmp_path, process_runner, isolated_environment, destination, message, preserved) -> None:
    pki = create_tree(tmp_path / "scope", process_runner, isolated_environment)
    paths = {"pki": pki, "parent": pki.parent, "services": pki / "services", "export": pki / "export"}
    result = run(process_runner, isolated_environment, "--pki-dir", pki, "--export-dir", paths[destination], "--force")
    assert result.status == 1
    assert message in result.stderr
    assert (pki / preserved).exists()


def test_export_force_rejects_unmarked_custom_directory(tmp_path, process_runner, isolated_environment) -> None:
    pki = create_tree(tmp_path / "unmarked-case", process_runner, isolated_environment)
    target = pki / "export/unmarked"
    target.mkdir(mode=0o700)
    (target / "sentinel").write_text("unmarked sentinel\n")
    result = run(process_runner, isolated_environment, "--pki-dir", pki, "--export-dir", target, "--force")
    assert result.status == 1
    assert "Refusing to replace unmarked custom export directory" in result.stderr
    assert (target / "sentinel").read_text() == "unmarked sentinel\n"


def test_export_force_rejects_nonprivate_existing_export(tmp_path, process_runner, isolated_environment) -> None:
    pki = create_tree(tmp_path / "nonprivate-case", process_runner, isolated_environment)
    export = pki / "export/ansible"
    sentinel = export / "sentinel"
    sentinel.write_text("nonprivate sentinel\n")
    export.chmod(0o755)

    result = run(process_runner, isolated_environment, "--pki-dir", pki, "--force")

    assert result.status == 1
    assert "does not satisfy its private path policy" in result.stderr
    assert sentinel.read_text() == "nonprivate sentinel\n"
    assert mode(export) == 0o755


def test_export_zero_generated_services_preserves_existing_export(tmp_path, process_runner, isolated_environment) -> None:
    pki = create_tree(tmp_path / "zero", process_runner, isolated_environment, services=())
    sentinel = pki / "export/ansible/sentinel"
    sentinel.write_text("zero sentinel\n")
    result = run(process_runner, isolated_environment, "--pki-dir", pki, "--force")
    assert result.status == 1
    assert "No generated service certificates found to export" in result.stderr
    assert sentinel.read_text() == "zero sentinel\n"


def test_all_service_export_skips_only_host_local_service_and_preserves_existing_export(tmp_path, process_runner, isolated_environment) -> None:
    pki = create_tree(tmp_path / "host-local-only", process_runner, isolated_environment, services=())
    write_private(
        pki / "inventory/services.yml",
        "services:\n  platform-host-local:\n    key_custody: host-local\n"
        "    target: host-01\n"
        "    validation_boundary_sha256: 0000000000000000000000000000000000000000000000000000000000000000\n"
        "    rollback_hold_seconds: 3600\n"
        "    common_name: platform-host-local.internal\n"
        "    dns:\n      - platform-host-local.internal\n",
    )
    sentinel = pki / "export/ansible/sentinel"
    sentinel.write_text("host-local-only sentinel\n")

    result = run(process_runner, isolated_environment, "--pki-dir", pki, "--force")

    assert result.status == 1
    assert "Skipping host-local service; Ansible export is managed-key-only: platform-host-local" in result.stderr
    assert "No generated service certificates found to export" in result.stderr
    assert sentinel.read_text() == "host-local-only sentinel\n"


def test_export_explicit_host_local_selection_preserves_existing_export(tmp_path, process_runner, isolated_environment) -> None:
    pki = create_tree(tmp_path / "host-local", process_runner, isolated_environment)
    sentinel = pki / "export/ansible/sentinel"
    sentinel.write_text("host-local sentinel\n")
    result = run(process_runner, isolated_environment, "platform-host-local", "--pki-dir", pki, "--force")
    assert result.status == 1
    assert "Host-local service cannot be exported through the managed-key Ansible export: platform-host-local" in result.stderr
    assert sentinel.read_text() == "host-local sentinel\n"


def test_export_copy_failure_does_not_publish_private_key_or_leave_temporary(tmp_path, process_runner, isolated_environment, executable_directory) -> None:
    pki = create_tree(tmp_path / "copy", process_runner, isolated_environment)
    fake_bin = executable_directory / "copy-bin"
    write_executable(fake_bin / "cp", """#!/usr/bin/env bash
set -euo pipefail
if [[ $1 == */private/tls.key ]]; then
  : >"$COPY_FAIL_MARKER"
  printf '%s\\n' 'partial private key' >"$2"
  exit 1
fi
exec "$REAL_CP" "$@"
""")
    target = pki / "export/copy-fail"
    marker = tmp_path / "copy-fail-triggered"
    result = run(process_runner, environment(isolated_environment, PATH=f"{fake_bin}:{isolated_environment['PATH']}", REAL_CP=executable("cp"), COPY_FAIL_MARKER=os.fspath(marker)), "platform-example", "--pki-dir", pki, "--export-dir", target, tool=ORACLE)
    assert result.status == 1
    assert marker.is_file()
    assert "Failed to publish export file without overwriting" in result.stderr
    assert not list(target.rglob(".tls.key.tmp.*"))
    assert not (target / "services/platform-example/tls.key").exists()


def write_race_ln(path: Path) -> None:
    write_executable(path, """#!/usr/bin/env bash
set -euo pipefail
target=${!#}
if { [[ ${RACE_TARGET_KIND:-payload} == payload && $target == */ca/root-ca.crt ]] ||
  [[ ${RACE_TARGET_KIND:-payload} == marker && $target == */.platform-pki-ansible-export ]]; } &&
  [[ ! -e $RACE_MARKER ]]; then
  case ${RACE_KIND:-file} in
    file) printf '%s\\n' 'attacker target' >"$target" ;;
    directory) mkdir "$target" ;;
    symlink)
      [[ -e $RACE_VICTIM ]] || mkdir "$RACE_VICTIM"
      "$REAL_LN" -s "$RACE_VICTIM" "$target"
      ;;
  esac
  : >"$RACE_MARKER"
fi
exec "$REAL_LN" "$@"
""")


@pytest.mark.parametrize("race_kind", ["file", "directory", "symlink"])
def test_export_payload_publication_race_preserves_attacker_target(tmp_path, process_runner, isolated_environment, executable_directory, race_kind) -> None:
    pki = create_tree(tmp_path / race_kind, process_runner, isolated_environment)
    fake_bin = executable_directory / "race-bin"
    write_race_ln(fake_bin / "ln")
    target = pki / f"export/{race_kind}-race"
    victim = tmp_path / "symlink-victim"
    marker = tmp_path / "race-marker"
    result = run(
        process_runner,
        environment(isolated_environment, PATH=f"{fake_bin}:{isolated_environment['PATH']}", REAL_LN=executable("ln"), RACE_MARKER=os.fspath(marker), RACE_KIND=race_kind, RACE_VICTIM=os.fspath(victim)),
        "platform-example", "--pki-dir", pki, "--export-dir", target, tool=ORACLE,
    )
    assert result.status == 1
    assert marker.is_file()
    raced = target / "ca/root-ca.crt"
    if race_kind == "file":
        assert raced.read_text() == "attacker target\n"
        assert not list(target.rglob(".root-ca.crt.tmp.*"))
    elif race_kind == "directory":
        assert raced.is_dir() and not any(raced.iterdir())
    else:
        assert raced.is_symlink() and victim.is_dir() and not any(victim.iterdir())


def test_export_marker_publication_race_does_not_modify_symlink_victim(tmp_path, process_runner, isolated_environment, executable_directory) -> None:
    pki = create_tree(tmp_path / "marker", process_runner, isolated_environment)
    fake_bin = executable_directory / "race-bin"
    write_race_ln(fake_bin / "ln")
    victim = tmp_path / "marker-victim"
    victim.write_text("marker victim sentinel\n")
    target = pki / "export/marker-race"
    marker = tmp_path / "marker-race-triggered"
    result = run(
        process_runner,
        environment(isolated_environment, PATH=f"{fake_bin}:{isolated_environment['PATH']}", REAL_LN=executable("ln"), RACE_MARKER=os.fspath(marker), RACE_TARGET_KIND="marker", RACE_KIND="symlink", RACE_VICTIM=os.fspath(victim)),
        "platform-example", "--pki-dir", pki, "--export-dir", target, tool=ORACLE,
    )
    assert result.status == 1
    assert marker.is_file()
    published_marker = target / ".platform-pki-ansible-export"
    assert published_marker.is_symlink()
    assert published_marker.readlink() == victim
    assert victim.read_text() == "marker victim sentinel\n"


@pytest.mark.parametrize("nested", [False, True], ids=["writable-parent", "writable-ancestor"])
def test_export_rejects_group_world_writable_ancestor(tmp_path, process_runner, isolated_environment, nested) -> None:
    pki = create_tree(tmp_path / "source", process_runner, isolated_environment)
    ancestor = tmp_path / "unsafe-parent"
    ancestor.mkdir()
    ancestor.chmod(0o777)
    parent = ancestor
    if nested:
        parent = ancestor / "safe-child"
        parent.mkdir(mode=0o700)
    result = run(process_runner, isolated_environment, "--pki-dir", pki, "--export-dir", parent / "export")
    assert result.status == 1
    assert "Export parent path component is group- or world-writable without sticky bit" in result.stderr


def write_fake_stat(path: Path) -> None:
    write_executable(path, """#!/bin/sh
if [ "$1" = '-c' ] && [ "$2" = '%u' ] && [ "${3:-}" = "$UNTRUSTED_COMPONENT" ]; then
  : >"$STAT_MARKER"
  printf '%s\\n' "$UNTRUSTED_OWNER"
  exit 0
fi
exec "$REAL_STAT" "$@"
""")


@pytest.mark.parametrize("sticky", [False, True], ids=["ordinary", "sticky"])
def test_export_rejects_untrusted_owner_ancestor_without_private_key_publication(tmp_path, process_runner, isolated_environment, executable_directory, sticky) -> None:
    pki = create_tree(tmp_path / "source", process_runner, isolated_environment)
    ancestor = tmp_path / "owner-ancestor"
    child = ancestor / "safe-child"
    child.mkdir(parents=True, mode=0o700)
    ancestor.chmod(0o1755 if sticky else 0o755)
    fake_bin = executable_directory / "fake-bin"
    write_fake_stat(fake_bin / "stat")
    owner = 99998 if os.getuid() == 99999 else 99999
    marker = tmp_path / "stat-triggered"
    result = run(
        process_runner,
        environment(isolated_environment, PATH=f"{fake_bin}:{isolated_environment['PATH']}", REAL_STAT=executable("stat"), STAT_MARKER=os.fspath(marker), UNTRUSTED_COMPONENT=os.fspath(ancestor), UNTRUSTED_OWNER=str(owner)),
        "--pki-dir", pki, "--export-dir", child / "export", tool=ORACLE,
    )
    assert result.status == 1
    assert marker.is_file()
    assert "Export parent path component is not owned by current user or root" in result.stderr
    assert not (child / "export/services/platform-example/tls.key").exists()


def test_export_rejects_symlink_export_directory(tmp_path, process_runner, isolated_environment) -> None:
    pki = create_tree(tmp_path / "source", process_runner, isolated_environment)
    target = tmp_path / "symlink-target"
    target.mkdir()
    shutil.rmtree(pki / "export/ansible")
    (pki / "export/ansible").symlink_to(target, target_is_directory=True)
    result = run(process_runner, isolated_environment, "--pki-dir", pki, "--force")
    assert result.status == 1
    assert "Export directory must not be a symlink" in result.stderr
    assert not (target / "services/platform-example/tls.key").exists()


def test_export_rejects_symlink_ancestor_component(tmp_path, process_runner, isolated_environment) -> None:
    pki = create_tree(tmp_path / "source", process_runner, isolated_environment)
    safe = tmp_path / "safe-parent"
    target = tmp_path / "ancestor-target"
    safe.mkdir(mode=0o700)
    (target / "sub").mkdir(parents=True, mode=0o700)
    (safe / "link").symlink_to(target, target_is_directory=True)
    result = run(process_runner, isolated_environment, "--pki-dir", pki, "--export-dir", safe / "link/sub/export")
    assert result.status == 1
    assert "Export parent path component must not be a symlink" in result.stderr
    assert not (target / "sub/export/services/platform-example/tls.key").exists()


def test_export_rejects_relative_path_from_symlink_cwd(tmp_path, process_runner, isolated_environment) -> None:
    pki = create_tree(tmp_path / "source", process_runner, isolated_environment)
    real = tmp_path / "real-cwd"
    alias = tmp_path / "link-cwd"
    real.mkdir()
    alias.symlink_to(real, target_is_directory=True)
    result = run(process_runner, isolated_environment, "--pki-dir", pki, "--export-dir", "relative-export", cwd=alias)
    assert result.status == 1
    assert "--export-dir must be an absolute path" in result.stderr
    assert not (real / "relative-export/services/platform-example/tls.key").exists()


def test_export_force_replaces_target_symlink_without_touching_victim(tmp_path, process_runner, isolated_environment) -> None:
    pki = create_tree(tmp_path / "source", process_runner, isolated_environment)
    victim = tmp_path / "attacker-file"
    victim.write_text("attacker content\n")
    target = pki / "export/ansible/services/platform-example/tls.key"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.symlink_to(victim)
    assert_result(run(process_runner, isolated_environment, "--pki-dir", pki, "--force"), 0)
    assert victim.read_text() == "attacker content\n"
    assert target.read_text() == "platform-example private key\n"
    assert not target.is_symlink()


@pytest.mark.parametrize("interface", ((TOOL,), (UNIFIED, "export-ansible")), ids=("compatibility", "unified"))
def test_python_interfaces_publish_complete_selected_export(tmp_path, process_runner, isolated_environment, interface) -> None:
    pki = create_tree(tmp_path / interface[0].name, process_runner, isolated_environment)
    target = pki / f"export/{interface[0].name}-selected"
    result = process_runner(
        [*interface, *SERVICES, "--pki-dir", pki, "--export-dir", target],
        env=isolated_environment,
        timeout=30,
    )
    assert_result(result, 0)
    assert result.stdout == "".join(
        f"[OK] Exported service: {service}\n" for service in SERVICES
    ) + f"[OK] Ansible export ready: {target}\n"
    assert result.stderr == f"[WARN] Export contains service private keys: {target}\n"
    assert not recovery_entries(target.parent)
    expected = {
        ".": ("directory", 0o700, None),
        ".platform-pki-ansible-export": (
            "file",
            0o600,
            b"platform-pki-export-ansible\n",
        ),
        "ca": ("directory", 0o700, None),
        "ca/root-ca.crt": (
            "file",
            0o644,
            (pki / "authorities/roots/g1/certs/root-ca.crt").read_bytes(),
        ),
        "services": ("directory", 0o700, None),
    }
    for service in SERVICES:
        expected[f"services/{service}"] = ("directory", 0o700, None)
        for exported, source, permissions in (
            ("tls.crt", "certs/tls.crt", 0o644),
            ("tls.key", "private/tls.key", 0o600),
            ("ca-chain.crt", "chain/ca-chain.crt", 0o644),
            ("fullchain.crt", "chain/fullchain.crt", 0o644),
        ):
            expected[f"services/{service}/{exported}"] = (
                "file",
                permissions,
                (pki / f"services/{service}/{source}").read_bytes(),
            )
    observed = {}
    for path in (target, *sorted(target.rglob("*"))):
        relative = "." if path == target else path.relative_to(target).as_posix()
        observed[relative] = (
            "directory" if path.is_dir() else "file",
            mode(path),
            None if path.is_dir() else path.read_bytes(),
        )
    assert observed == expected


@pytest.mark.parametrize("point", ("export-before-stage-build", "export-after-stage-build", "tree-before-parent-fsync"))
def test_python_prepublication_fault_preserves_existing_export_and_retains_unready_stage(tmp_path, process_runner, isolated_environment, point) -> None:
    pki = create_tree(tmp_path / point, process_runner, isolated_environment)
    export = pki / "export/ansible"
    sentinel = export / "sentinel"
    sentinel.write_text("old export\n")
    before = (export.stat().st_ino, sentinel.read_bytes(), sentinel.stat().st_ino)
    result = run(
        process_runner,
        python_environment(isolated_environment, PLATFORM_PKI_EXPORT_ANSIBLE_FAIL_AT=point),
        "--pki-dir", pki, "--force",
    )
    assert result.status == 1
    assert (export.stat().st_ino, sentinel.read_bytes(), sentinel.stat().st_ino) == before
    retained = recovery_entries(export.parent)
    assert len(retained) == 1
    assert mode(retained[0]) == 0o700
    assert os.fspath(retained[0]) in result.stderr


@pytest.mark.parametrize("mutation", ("contents", "inode"))
def test_python_custom_marker_replacement_before_exchange_preserves_old_destination(
    tmp_path,
    process_runner,
    process_starter,
    isolated_environment,
    mutation,
) -> None:
    pki = create_tree(tmp_path / mutation, process_runner, isolated_environment)
    target = pki / "export/custom"
    assert_result(
        run(
            process_runner,
            isolated_environment,
            "platform-example",
            "--pki-dir",
            pki,
            "--export-dir",
            target,
        ),
        0,
    )
    old_inode = target.stat().st_ino
    old_key = (target / "services/platform-example/tls.key").read_bytes()
    source_key = pki / "services/platform-example/private/tls.key"
    source_key.write_text("new private key\n")
    marker = tmp_path / f"{mutation}-marker"
    release = tmp_path / f"{mutation}-release"
    process = process_starter(
        [
            TOOL,
            "platform-example",
            "--pki-dir",
            pki,
            "--export-dir",
            target,
            "--force",
        ],
        env=python_environment(
            isolated_environment,
            PLATFORM_PKI_EXPORT_ANSIBLE_PAUSE_AT="replacement-before-final-authorization",
            PLATFORM_PKI_EXPORT_ANSIBLE_PAUSE_MARKER=os.fspath(marker),
            PLATFORM_PKI_EXPORT_ANSIBLE_PAUSE_RELEASE=os.fspath(release),
        ),
        timeout=30,
    )
    wait_for_path(marker)
    authorization = target / ".platform-pki-ansible-export"
    if mutation == "contents":
        authorization.write_bytes(b"changed authorization\n")
    else:
        authorization.rename(target / ".saved-authorization-marker")
        authorization.write_bytes(b"platform-pki-export-ansible\n")
        authorization.chmod(0o600)
    release.touch()
    result = process.wait()

    assert result.status == 1
    assert target.stat().st_ino == old_inode
    assert (target / "services/platform-example/tls.key").read_bytes() == old_key
    assert not recovery_entries(target.parent)


def test_python_source_race_preserves_existing_export_and_removes_stage(tmp_path, process_runner, process_starter, isolated_environment) -> None:
    pki = create_tree(tmp_path / "source-race", process_runner, isolated_environment)
    export = pki / "export/ansible"
    sentinel = export / "sentinel"
    sentinel.write_text("old export\n")
    source = pki / "services/platform-example/private/tls.key"
    marker = tmp_path / "source-race-marker"
    release = tmp_path / "source-race-release"
    process = process_starter(
        [TOOL, "--pki-dir", pki, "--force"],
        env=python_environment(
            isolated_environment,
            PLATFORM_PKI_EXPORT_ANSIBLE_PAUSE_AT="export-before-source-recheck",
            PLATFORM_PKI_EXPORT_ANSIBLE_PAUSE_MARKER=os.fspath(marker),
            PLATFORM_PKI_EXPORT_ANSIBLE_PAUSE_RELEASE=os.fspath(release),
        ),
        timeout=30,
    )
    wait_for_path(marker)
    source.write_text("changed source bytes\n")
    release.touch()
    result = process.wait()
    assert result.status == 1
    assert sentinel.read_text() == "old export\n"
    assert not recovery_entries(export.parent)


def test_python_competing_destination_preserves_winner_and_removes_stage(tmp_path, process_runner, process_starter, isolated_environment) -> None:
    pki = create_tree(tmp_path / "destination-race", process_runner, isolated_environment)
    target = pki / "export/winner"
    marker = tmp_path / "destination-race-marker"
    release = tmp_path / "destination-race-release"
    process = process_starter(
        [TOOL, "platform-example", "--pki-dir", pki, "--export-dir", target],
        env=python_environment(
            isolated_environment,
            PLATFORM_PKI_EXPORT_ANSIBLE_PAUSE_AT="publication-before-mutation",
            PLATFORM_PKI_EXPORT_ANSIBLE_PAUSE_MARKER=os.fspath(marker),
            PLATFORM_PKI_EXPORT_ANSIBLE_PAUSE_RELEASE=os.fspath(release),
        ),
        timeout=30,
    )
    wait_for_path(marker)
    target.mkdir(mode=0o700)
    (target / "winner").write_text("winner\n")
    release.touch()
    result = process.wait()
    assert result.status == 1
    assert (target / "winner").read_text() == "winner\n"
    assert not recovery_entries(target.parent)


def test_python_prepublication_cleanup_race_retains_private_stage_evidence(
    tmp_path, process_runner, process_starter, isolated_environment
) -> None:
    pki = create_tree(tmp_path / "stage-cleanup-race", process_runner, isolated_environment)
    export = pki / "export/ansible"
    sentinel = export / "sentinel"
    sentinel.write_text("old export\n")
    old_inode = export.stat().st_ino
    marker = tmp_path / "stage-cleanup-marker"
    release = tmp_path / "stage-cleanup-release"
    process = process_starter(
        [TOOL, "--pki-dir", pki, "--force"],
        env=python_environment(
            isolated_environment,
            PLATFORM_PKI_EXPORT_ANSIBLE_FAIL_AT="export-before-source-recheck",
            PLATFORM_PKI_EXPORT_ANSIBLE_PAUSE_AT="tree-cleanup-before-entry-unlink",
            PLATFORM_PKI_EXPORT_ANSIBLE_PAUSE_MARKER=os.fspath(marker),
            PLATFORM_PKI_EXPORT_ANSIBLE_PAUSE_RELEASE=os.fspath(release),
        ),
        timeout=30,
    )
    wait_for_path(marker)
    retained = recovery_entries(export.parent)
    assert len(retained) == 1
    stage = retained[0]
    staged_marker = stage / ".platform-pki-ansible-export"
    staged_marker.rename(tmp_path / "saved-stage-marker")
    write_private(staged_marker, "replacement stage marker\n")
    release.touch()
    result = process.wait()

    assert result.status == 1
    assert export.stat().st_ino == old_inode
    assert sentinel.read_text() == "old export\n"
    assert stage.is_dir() and mode(stage) == 0o700
    assert (stage / "services/platform-example/tls.key").read_text() == "platform-example private key\n"
    assert mode(stage / "services/platform-example/tls.key") == 0o600
    assert os.fspath(stage) in result.stderr


def test_python_postpublication_failure_keeps_new_export_and_retains_exact_old_tree(tmp_path, process_runner, isolated_environment) -> None:
    pki = create_tree(tmp_path / "post-publication", process_runner, isolated_environment)
    export = pki / "export/ansible"
    sentinel = export / "sentinel"
    sentinel.write_text("old export\n")
    old_inode = export.stat().st_ino
    result = run(
        process_runner,
        python_environment(
            isolated_environment,
            PLATFORM_PKI_EXPORT_ANSIBLE_FAIL_AT="replacement-after-exchange",
        ),
        "--pki-dir", pki, "--force",
    )
    assert result.status == 1
    assert (export / "services/platform-example/tls.key").read_text() == "platform-example private key\n"
    retained = recovery_entries(export.parent)
    assert len(retained) == 1
    assert retained[0].stat().st_ino == old_inode
    assert (retained[0] / "sentinel").read_text() == "old export\n"
    assert os.fspath(retained[0]) in result.stderr


def test_python_cleanup_fault_retains_old_export_and_hostile_symlink_without_touching_victim(tmp_path, process_runner, isolated_environment) -> None:
    pki = create_tree(tmp_path / "cleanup", process_runner, isolated_environment)
    export = pki / "export/ansible"
    victim = tmp_path / "victim"
    victim.write_text("victim\n")
    hostile = export / "hostile"
    hostile.symlink_to(victim)
    old_inode = export.stat().st_ino
    result = run(
        process_runner,
        python_environment(
            isolated_environment,
            PLATFORM_PKI_EXPORT_ANSIBLE_FAIL_AT="tree-cleanup-before-mutation",
        ),
        "--pki-dir", pki, "--force",
    )
    assert result.status == 1
    assert victim.read_text() == "victim\n"
    retained = recovery_entries(export.parent)
    assert len(retained) == 1
    assert retained[0].stat().st_ino == old_inode
    assert (retained[0] / "hostile").is_symlink()
    assert (export / "services/platform-example/tls.key").is_file()
    assert os.fspath(retained[0]) in result.stderr


def test_python_postexchange_cleanup_race_keeps_new_export_and_old_private_key_evidence(
    tmp_path, process_runner, process_starter, isolated_environment
) -> None:
    pki = create_tree(tmp_path / "postexchange-cleanup-race", process_runner, isolated_environment)
    export = pki / "export/ansible"
    assert_result(run(process_runner, isolated_environment, "--pki-dir", pki, "--force"), 0)
    old_inode = export.stat().st_ino
    old_key = (export / "services/platform-example/tls.key").read_bytes()
    (pki / "services/platform-example/private/tls.key").write_text("new private key\n")
    marker = tmp_path / "postexchange-cleanup-marker"
    release = tmp_path / "postexchange-cleanup-release"
    process = process_starter(
        [TOOL, "--pki-dir", pki, "--force"],
        env=python_environment(
            isolated_environment,
            PLATFORM_PKI_EXPORT_ANSIBLE_PAUSE_AT="tree-cleanup-before-entry-unlink",
            PLATFORM_PKI_EXPORT_ANSIBLE_PAUSE_MARKER=os.fspath(marker),
            PLATFORM_PKI_EXPORT_ANSIBLE_PAUSE_RELEASE=os.fspath(release),
        ),
        timeout=30,
    )
    wait_for_path(marker)
    retained = recovery_entries(export.parent)
    assert len(retained) == 1
    displaced = retained[0]
    displaced_marker = displaced / ".platform-pki-ansible-export"
    displaced_marker.rename(tmp_path / "saved-displaced-marker")
    write_private(displaced_marker, "replacement displaced marker\n")
    release.touch()
    result = process.wait()

    assert result.status == 1
    assert export.stat().st_ino != old_inode
    assert (export / "services/platform-example/tls.key").read_text() == "new private key\n"
    assert displaced.is_dir() and displaced.stat().st_ino == old_inode
    assert (displaced / "services/platform-example/tls.key").read_bytes() == old_key
    assert os.fspath(displaced) in result.stderr


def test_python_prepublication_crash_preserves_old_export_and_private_stage(
    tmp_path, process_runner, isolated_environment
) -> None:
    pki = create_tree(tmp_path / "prepublication-crash", process_runner, isolated_environment)
    export = pki / "export/ansible"
    sentinel = export / "sentinel"
    sentinel.write_text("old export\n")
    old_inode = export.stat().st_ino

    result = run(
        process_runner,
        python_environment(
            isolated_environment,
            PLATFORM_PKI_EXPORT_ANSIBLE_CRASH_AT="export-after-stage-build",
        ),
        "--pki-dir",
        pki,
        "--force",
    )

    assert result.status == 137
    assert export.stat().st_ino == old_inode
    assert sentinel.read_text() == "old export\n"
    retained = recovery_entries(export.parent)
    assert len(retained) == 1 and mode(retained[0]) == 0o700
    assert (retained[0] / "services/platform-example/tls.key").read_text() == "platform-example private key\n"


def test_python_final_preexchange_crash_preserves_exact_old_export(
    tmp_path, process_runner, isolated_environment
) -> None:
    pki = create_tree(tmp_path / "final-preexchange-crash", process_runner, isolated_environment)
    export = pki / "export/ansible"
    sentinel = export / "sentinel"
    sentinel.write_text("old export\n")
    before = (export.stat().st_ino, sentinel.stat().st_ino, sentinel.read_bytes())

    result = run(
        process_runner,
        python_environment(
            isolated_environment,
            PLATFORM_PKI_EXPORT_ANSIBLE_CRASH_AT="replacement-before-final-authorization",
        ),
        "--pki-dir",
        pki,
        "--force",
    )

    assert result.status == 137
    assert (export.stat().st_ino, sentinel.stat().st_ino, sentinel.read_bytes()) == before
    retained = recovery_entries(export.parent)
    assert len(retained) == 1 and mode(retained[0]) == 0o700
    assert (retained[0] / "services/platform-example/tls.key").read_text() == (
        "platform-example private key\n"
    )


def test_python_postexchange_crash_keeps_new_export_and_exact_displaced_tree(
    tmp_path, process_runner, isolated_environment
) -> None:
    pki = create_tree(tmp_path / "postexchange-crash", process_runner, isolated_environment)
    export = pki / "export/ansible"
    assert_result(run(process_runner, isolated_environment, "--pki-dir", pki, "--force"), 0)
    old_inode = export.stat().st_ino
    old_key = (export / "services/platform-example/tls.key").read_bytes()
    (pki / "services/platform-example/private/tls.key").write_text("new private key\n")

    result = run(
        process_runner,
        python_environment(
            isolated_environment,
            PLATFORM_PKI_EXPORT_ANSIBLE_CRASH_AT="replacement-after-exchange",
        ),
        "--pki-dir",
        pki,
        "--force",
    )

    assert result.status == 137
    assert export.stat().st_ino != old_inode
    assert (export / "services/platform-example/tls.key").read_text() == "new private key\n"
    retained = recovery_entries(export.parent)
    assert len(retained) == 1 and retained[0].stat().st_ino == old_inode
    assert (retained[0] / "services/platform-example/tls.key").read_bytes() == old_key


def test_python_successful_replacement_unlinks_hostile_symlink_entry_only(tmp_path, process_runner, isolated_environment) -> None:
    pki = create_tree(tmp_path / "symlink-cleanup", process_runner, isolated_environment)
    export = pki / "export/ansible"
    victim = tmp_path / "victim-directory"
    victim.mkdir()
    (victim / "sentinel").write_text("victim\n")
    (export / "hostile").symlink_to(victim, target_is_directory=True)
    assert_result(run(process_runner, isolated_environment, "--pki-dir", pki, "--force"), 0)
    assert (victim / "sentinel").read_text() == "victim\n"
    assert not recovery_entries(export.parent)


def _normalize_case_root(root: Path, output: str) -> str:
    return output.replace(os.fspath(root), "<CASE>")


def _run_export_differential(seed: Path, case: Path, isolated_environment, arguments=(), export_relative: Path | None = None):
    effective = {
        **isolated_environment,
        "PLATFORM_TOOLS_LIB_DIR": os.fspath(REPOSITORY / "lib"),
    }
    def command(root: Path, interface: tuple[Path | str, ...]):
        values: list[Path | str] = [
            *interface,
            *arguments,
            "--pki-dir",
            root / "pki",
            "--force",
        ]
        if export_relative is not None:
            values.extend(("--export-dir", root / export_relative))
        return tuple(values)

    return run_differential_case(
        seed,
        case,
        Path("pki"),
        lambda root: command(root, (ORACLE,)),
        lambda root: command(root, (UNIFIED, "export-ansible")),
        effective,
        output_normalizers=(_normalize_case_root,),
        run_options={"timeout": 30},
    )


def test_bash_python_success_selection_and_warning_are_equivalent(tmp_path, process_runner, isolated_environment) -> None:
    seed = tmp_path / "seed"
    create_tree(seed, process_runner, isolated_environment)
    all_services = _run_export_differential(
        seed,
        tmp_path / "all-services-case",
        isolated_environment,
        export_relative=Path("pki/export/all-services"),
    )
    all_services.assert_equivalent()

    selected = _run_export_differential(
        seed,
        tmp_path / "selected-case",
        isolated_environment,
        arguments=tuple(reversed(SERVICES)),
        export_relative=Path("pki/export/selected"),
    )
    selected.assert_equivalent()
    assert selected.python.process.stdout.startswith(
        "[OK] Exported service: platform-second\n"
        "[OK] Exported service: platform-example\n"
    )

    custom_seed = tmp_path / "custom-seed"
    custom_pki = create_tree(custom_seed, process_runner, isolated_environment)
    custom = custom_pki / "export/custom"
    custom.mkdir(mode=0o700)
    write_private(custom / ".platform-pki-ansible-export", "platform-pki-export-ansible\n")
    write_private(custom / "stale", "stale\n")
    authorized = _run_export_differential(
        custom_seed,
        tmp_path / "custom-authorized-case",
        isolated_environment,
        export_relative=Path("pki/export/custom"),
    )
    assert authorized.bash.process == authorized.python.process
    assert authorized.bash.before == authorized.python.before
    assert authorized.bash.after == authorized.python.after


def test_bash_python_host_local_and_generation_gate_failures_are_equivalent(tmp_path, process_runner, isolated_environment) -> None:
    seed = tmp_path / "host-local-seed"
    create_tree(seed, process_runner, isolated_environment)
    host_local = _run_export_differential(
        seed,
        tmp_path / "host-local-case",
        isolated_environment,
        arguments=("platform-host-local",),
    )
    host_local.assert_equivalent()

    legacy = tmp_path / "legacy-seed"
    pki = create_tree(legacy, process_runner, isolated_environment)
    shutil.rmtree(pki / "authorities")
    (pki / "state/active-issuer").unlink()
    (pki / "root-ca").mkdir(mode=0o700)
    (pki / "intermediate-ca").mkdir(mode=0o700)
    gated = _run_export_differential(
        legacy, tmp_path / "legacy-case", isolated_environment
    )
    gated.assert_equivalent()


def test_bash_python_path_and_issuer_failures_are_equivalent(
    tmp_path, process_runner, isolated_environment
) -> None:
    boundary_seed = tmp_path / "boundary-seed"
    create_tree(boundary_seed, process_runner, isolated_environment)
    boundary = _run_export_differential(
        boundary_seed,
        tmp_path / "boundary-case",
        isolated_environment,
        export_relative=Path("pki/services"),
    )
    boundary.assert_equivalent()

    issuer_seed = tmp_path / "issuer-seed"
    issuer_pki = create_tree(issuer_seed, process_runner, isolated_environment)
    (issuer_pki / "export/ansible/sentinel").write_text("preserved issuer failure\n")
    write_private(issuer_pki / "services/platform-example/issuer", "invalid issuer\n")
    issuer = _run_export_differential(
        issuer_seed,
        tmp_path / "issuer-case",
        isolated_environment,
        arguments=("platform-example",),
    )
    assert issuer.bash.process == issuer.python.process
    assert issuer.bash.before == issuer.python.before
    assert (
        tmp_path / "issuer-case/python/pki/export/ansible/sentinel"
    ).read_text() == "preserved issuer failure\n"
    assert not (
        tmp_path / "issuer-case/bash/pki/export/ansible/sentinel"
    ).exists()
