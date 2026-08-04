from __future__ import annotations

import os
import shutil
from collections.abc import Callable, Mapping
from pathlib import Path

import pytest

from ..harness import ProcessResult
from .support import BIN, REPOSITORY, assert_result, environment, executable, executable_directory, mode, write_executable, write_private


pytestmark = pytest.mark.pki
TOOL = BIN / "platform-pki-export-ansible"
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
"""


def run(process_runner: Callable[..., ProcessResult], env: Mapping[str, str], *arguments: object, cwd: Path | None = None) -> ProcessResult:
    return process_runner([TOOL, *arguments], env=env, cwd=cwd, timeout=30)


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


def test_export_zero_generated_services_preserves_existing_export(tmp_path, process_runner, isolated_environment) -> None:
    pki = create_tree(tmp_path / "zero", process_runner, isolated_environment, services=())
    sentinel = pki / "export/ansible/sentinel"
    sentinel.write_text("zero sentinel\n")
    result = run(process_runner, isolated_environment, "--pki-dir", pki, "--force")
    assert result.status == 1
    assert "No generated service certificates found to export" in result.stderr
    assert sentinel.read_text() == "zero sentinel\n"


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
    result = run(process_runner, environment(isolated_environment, PATH=f"{fake_bin}:{isolated_environment['PATH']}", REAL_CP=executable("cp"), COPY_FAIL_MARKER=os.fspath(marker)), "platform-example", "--pki-dir", pki, "--export-dir", target)
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
        "platform-example", "--pki-dir", pki, "--export-dir", target,
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
        "platform-example", "--pki-dir", pki, "--export-dir", target,
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
        "--pki-dir", pki, "--export-dir", child / "export",
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
