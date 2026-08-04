from __future__ import annotations

import os
import stat
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

import pytest

from ..harness import ProcessResult
from .support import BIN, REPOSITORY, assert_result, digest, environment, executable, executable_directory, write_executable, write_private


pytestmark = pytest.mark.pki
INIT = BIN / "platform-pki-init"
ROOT = BIN / "platform-pki-root-create"
INTERMEDIATE = BIN / "platform-pki-intermediate-create"
ISSUE = BIN / "platform-pki-service-issue"
TOOL = BIN / "platform-pki-service-renew"
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
    ips:
      - 192.0.2.11
  failure:
    common_name: failure.example.internal
    dns:
      - failure.example.internal
    ips:
      - 192.0.2.12
  keyonly:
    common_name: keyonly.example.internal
    dns:
      - keyonly.example.internal
"""


@dataclass(frozen=True)
class Workspace:
    namespace: Path
    pki: Path
    root_pass: Path
    intermediate_pass: Path
    env: Mapping[str, str]
    runner: Callable[..., ProcessResult]

    def renew(self, service: str, *arguments: object, env: Mapping[str, str] | None = None) -> ProcessResult:
        return self.runner(
            [TOOL, service, "--namespace", self.namespace, *arguments, "--intermediate-pass-file", self.intermediate_pass],
            env=self.env if env is None else env,
            timeout=120,
        )

    def issue(self, service: str) -> None:
        result = self.runner(
            [ISSUE, service, "--namespace", self.namespace, "--intermediate-pass-file", self.intermediate_pass],
            env=self.env,
            timeout=120,
        )
        assert_result(result, 0)


@pytest.fixture
def renew_workspace(tmp_path, process_runner, isolated_environment) -> Workspace:
    namespace = tmp_path / "namespace"
    pki = namespace / "pki"
    root_pass = tmp_path / "root.pass"
    intermediate_pass = tmp_path / "intermediate.pass"
    write_private(root_pass, "root-test-passphrase-123\n")
    write_private(intermediate_pass, "intermediate-test-passphrase-123\n")
    commands = (
        [INIT, "--namespace", namespace],
        [ROOT, "--namespace", namespace, "--name", "Test Root CA", "--org", "Test", "--country", "PL", "--root-pass-file", root_pass],
        [INTERMEDIATE, "--namespace", namespace, "--name", "Test Intermediate CA", "--org", "Test", "--country", "PL", "--root-pass-file", root_pass, "--intermediate-pass-file", intermediate_pass],
    )
    assert_result(process_runner(commands[0], env=isolated_environment, timeout=120), 0)
    write_private(pki / "inventory/services.yml", INVENTORY)
    for command in commands[1:]:
        assert_result(process_runner(command, env=isolated_environment, timeout=120), 0)
    return Workspace(namespace, pki, root_pass, intermediate_pass, isolated_environment, process_runner)


def no_residue(pki: Path) -> None:
    assert not (pki / "authorities/roots/g1/.platform-pki-root-operation.lock").exists()
    assert not (pki / "authorities/intermediates/g1-i1/.platform-pki-intermediate-operation.lock").exists()
    assert not list((pki / "authorities/intermediates/g1-i1").glob(".platform-pki-service-renew.*"))


def openssl(workspace: Workspace, *arguments: object) -> ProcessResult:
    return workspace.runner(["openssl", *arguments], env=workspace.env, timeout=30)


def canonical_serial(serial: str) -> str:
    value = serial.strip().upper()
    while value.startswith("00") and len(value) > 2:
        value = value[2:]
    return value


def path_record(path: Path) -> tuple[object, ...]:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return (os.fspath(path), "absent")
    common = (stat.S_IMODE(metadata.st_mode), metadata.st_uid, metadata.st_gid, metadata.st_mtime_ns)
    if stat.S_ISLNK(metadata.st_mode):
        return (os.fspath(path), "symlink", *common, os.readlink(path))
    if stat.S_ISREG(metadata.st_mode):
        return (os.fspath(path), "file", *common, metadata.st_size, sha256(path.read_bytes()).hexdigest())
    if stat.S_ISDIR(metadata.st_mode):
        return (os.fspath(path), "directory", *common)
    return (os.fspath(path), "other", stat.S_IFMT(metadata.st_mode), *common)


def state_snapshot(service: Path, pki: Path, newcert: Path) -> tuple[tuple[object, ...], ...]:
    authority = pki / "authorities/intermediates/g1-i1"
    archive = service / "archive"
    paths = [
        service / "private/tls.key", service / "certs/tls.crt", service / "csr/tls.csr",
        service / "openssl.cnf", service / "chain/ca-chain.crt", service / "chain/fullchain.crt",
        service / "issuer",
        authority / "index.txt", authority / "index.txt.attr", authority / "serial", authority / "crlnumber",
        authority / "index.txt.old", authority / "index.txt.attr.old", authority / "serial.old", newcert, archive,
    ]
    if archive.is_dir():
        paths.extend(sorted(archive.rglob("*")))
    return tuple(path_record(path) for path in paths)


def test_service_renew_cli_contract(tmp_path, process_runner, isolated_environment) -> None:
    version = (REPOSITORY / "VERSION").read_text().strip()
    result = process_runner([TOOL, "--help"], env=isolated_environment, timeout=30)
    assert_result(result, 0, stderr="")
    assert "platform-pki-service-renew --version | -v" in result.stdout
    assert "--rotate-key" in result.stdout
    assert_result(process_runner([TOOL, "--version"], env=isolated_environment, timeout=30), 0, stdout=f"platform-pki-service-renew {version}\n")
    result = process_runner([TOOL], env=isolated_environment, timeout=30)
    assert result.status == 1 and "missing required argument: SERVICE" in result.stderr
    result = process_runner([TOOL, "app", "--days", "nope"], env=isolated_environment, timeout=30)
    assert result.status == 1 and "Days value must be numeric: nope" in result.stderr
    for flag in ("--help", "-h"):
        result = process_runner([TOOL, "app", flag], env=isolated_environment, timeout=30)
        assert_result(result, 0, stderr="")
        assert "Usage:" in result.stdout
    result = process_runner([TOOL, "app", "--namespace", "--help"], env=isolated_environment, timeout=30)
    assert_result(result, 1, stdout="")


def test_service_renew_requires_issued_service_state(renew_workspace: Workspace) -> None:
    result = renew_workspace.renew("app")
    assert result.status == 1
    assert "Service private key is missing; use platform-pki-service-issue first" in result.stderr
    assert not (renew_workspace.pki / "services/app").exists()


def test_service_renew_reuses_key_archives_material_and_honors_inventory_days(renew_workspace: Workspace) -> None:
    workspace = renew_workspace
    workspace.issue("app")
    service = workspace.pki / "services/app"
    key = service / "private/tls.key"
    certificate = service / "certs/tls.crt"
    old_key = digest(key)
    old_certificate = digest(certificate)
    old_serial = openssl(workspace, "x509", "-in", certificate, "-noout", "-serial")
    assert_result(old_serial, 0)

    result = workspace.renew("app")
    assert_result(result, 0)
    assert "[OK] Verified service certificate: app" in result.stdout
    assert "[OK] Renewed service certificate:" in result.stdout
    assert digest(key) == old_key
    assert digest(certificate) != old_certificate
    new_serial = openssl(workspace, "x509", "-in", certificate, "-noout", "-serial")
    assert_result(new_serial, 0)
    assert new_serial.stdout != old_serial.stdout
    archives = list((service / "archive").iterdir())
    assert len(archives) == 1
    archive = archives[0]
    for name in ("tls.crt", "tls.csr", "ca-chain.crt", "fullchain.crt", "openssl.cnf", "issuer"):
        assert (archive / name).is_file()
    assert digest(archive / "tls.crt") == old_certificate
    verify = openssl(workspace, "verify", "-CAfile", workspace.pki / "authorities/roots/g1/certs/root-ca.crt", "-untrusted", workspace.pki / "authorities/intermediates/g1-i1/certs/intermediate-ca.crt", certificate)
    assert_result(verify, 0)
    assert_result(openssl(workspace, "x509", "-in", certificate, "-checkend", str(34 * 86400), "-noout"), 0)
    assert openssl(workspace, "x509", "-in", certificate, "-checkend", str(36 * 86400), "-noout").status != 0
    assert (service / "issuer").read_text() == "root=g1\nintermediate=g1-i1\n"
    assert (archive / "issuer").read_text() == "root=g1\nintermediate=g1-i1\n"
    no_residue(workspace.pki)


def test_service_renew_key_only_state_archives_only_issuer(renew_workspace: Workspace) -> None:
    workspace = renew_workspace
    workspace.issue("keyonly")
    service = workspace.pki / "services/keyonly"
    missing = (
        service / "certs/tls.crt", service / "csr/tls.csr", service / "chain/ca-chain.crt",
        service / "chain/fullchain.crt", service / "openssl.cnf",
    )
    for path in missing:
        path.unlink()
    result = workspace.renew("keyonly")
    assert_result(result, 0)
    for path in (*missing, service / "private/tls.key"):
        assert f"Archived {path} to " not in result.stdout
    archives = list((service / "archive").iterdir())
    assert len(archives) == 1
    files = [path for path in archives[0].iterdir() if path.is_file()]
    assert [path.name for path in files] == ["issuer"]


def test_service_renew_rotate_key_archives_old_key(renew_workspace: Workspace) -> None:
    workspace = renew_workspace
    workspace.issue("rotate")
    key = workspace.pki / "services/rotate/private/tls.key"
    old_key = digest(key)
    result = workspace.renew("rotate", "--days", "31", "--rotate-key")
    assert_result(result, 0)
    assert digest(key) != old_key
    archive_keys = list((workspace.pki / "services/rotate/archive").glob("*/tls.key"))
    assert len(archive_keys) == 1
    assert digest(archive_keys[0]) == old_key


def prepare_failure_state(workspace: Workspace) -> tuple[Path, Path, tuple[tuple[object, ...], ...]]:
    workspace.issue("failure")
    service = workspace.pki / "services/failure"
    previous = service / "archive/previous"
    previous.mkdir(mode=0o700, parents=True)
    previous.parent.chmod(0o700)
    write_private(previous / "sentinel", "existing archive sentinel\n")
    timestamp = 1577934245
    os.utime(previous / "sentinel", (timestamp, timestamp))
    os.utime(previous, (timestamp, timestamp))
    os.utime(previous.parent, (timestamp, timestamp))
    authority = workspace.pki / "authorities/intermediates/g1-i1"
    newcert = authority / "newcerts" / f"{canonical_serial((authority / 'serial').read_text())}.pem"
    return service, newcert, state_snapshot(service, workspace.pki, newcert)


def test_service_renew_signing_failure_restores_complete_state(renew_workspace: Workspace, executable_directory) -> None:
    workspace = renew_workspace
    service, newcert, before = prepare_failure_state(workspace)
    fake_bin = executable_directory / "failing-bin"
    write_executable(fake_bin / "openssl", """#!/usr/bin/env bash
[[ ${1:-} != ca ]] || exit 42
exec "$REAL_OPENSSL" "$@"
""")
    result = workspace.renew("failure", "--rotate-key", env=environment(workspace.env, PATH=f"{fake_bin}:{workspace.env['PATH']}", REAL_OPENSSL=executable("openssl")))
    assert result.status == 42
    assert state_snapshot(service, workspace.pki, newcert) == before
    no_residue(workspace.pki)


def test_service_renew_verification_failure_restores_complete_state(renew_workspace: Workspace, executable_directory) -> None:
    workspace = renew_workspace
    service, newcert, before = prepare_failure_state(workspace)
    fake_lib = executable_directory / "verify-lib"
    write_executable(fake_lib / "platform-pki-common.sh", """#!/usr/bin/env bash
source "$REAL_COMMON"
pki_verify_service_certificate() { exit 43; }
""")
    result = workspace.renew("failure", "--rotate-key", env=environment(workspace.env, REAL_COMMON=os.fspath(REPOSITORY / "lib/platform-pki-common.sh"), PLATFORM_TOOLS_LIB_DIR=os.fspath(fake_lib)))
    assert result.status == 43
    assert state_snapshot(service, workspace.pki, newcert) == before
    no_residue(workspace.pki)
