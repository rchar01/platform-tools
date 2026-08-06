from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from pathlib import Path

import pytest

from ..harness import ProcessResult
from .support import BIN, REPOSITORY, assert_result, environment, executable, executable_directory, mode, write_executable, write_private


pytestmark = pytest.mark.pki
TOOL = BIN / "platform-pki-backup"


def run(process_runner: Callable[..., ProcessResult], env: Mapping[str, str], *arguments: object) -> ProcessResult:
    return process_runner([TOOL, *arguments], env=env, timeout=30)


def create_legacy_pki(pki: Path) -> None:
    for directory in (pki / "inventory", pki / "root-ca", pki / "intermediate-ca"):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    pki.chmod(0o700)
    write_private(
        pki / "inventory/services.yml",
        "services:\n  backup-test:\n    key_custody: host-local\n"
        "    common_name: backup.example.internal\n"
        "    dns:\n      - backup.example.internal\n",
    )
    write_private(pki / "private-state", "private state sentinel\n")


def fake_age(path: Path) -> None:
    write_executable(path, """#!/usr/bin/env bash
set -euo pipefail
output=''
input=''
for arg in "$@"; do printf '<%s>\\n' "$arg" >>"$AGE_LOG"; done
while [[ $# -gt 0 ]]; do
  case $1 in
    -r) shift 2 ;;
    -o) output=$2; shift 2 ;;
    -p) shift ;;
    *) input=$1; shift ;;
  esac
done
[[ -n $output && -n $input ]]
cp "$input" "$output"
if [[ ${AGE_FAIL:-0} == 1 ]]; then
  printf '%s\\n' 'partial encrypted output' >"$output"
  exit 1
fi
""")


def latest(directory: Path, suffix: str) -> Path:
    matches = sorted(directory.glob(f"platform-pki-*{suffix}"))
    assert matches
    return matches[-1]


def assert_age_argv(
    log: Path,
    backup_directory: Path,
    prefix: list[str],
) -> None:
    logged = log.read_text().splitlines()
    assert len(logged) == len(prefix) + 2
    encrypted = Path(logged[-2][1:-1])
    archive = Path(logged[-1][1:-1])
    assert encrypted.name == "platform-pki.tar.gz.age"
    assert archive.name == "platform-pki.tar.gz"
    assert encrypted.parent == archive.parent
    assert encrypted.parent.parent == backup_directory
    assert encrypted.parent.name.startswith(".platform-pki-backup.")
    assert logged == [
        *(f"<{argument}>" for argument in prefix),
        f"<{encrypted}>",
        f"<{archive}>",
    ]


def test_backup_cli_contract(tmp_path, process_runner, isolated_environment) -> None:
    version = (REPOSITORY / "VERSION").read_text().strip()
    result = run(process_runner, isolated_environment, "--help")
    assert_result(result, 0, stderr="")
    assert "Usage:" in result.stdout
    assert "platform-pki-backup --version | -v" in result.stdout
    assert_result(run(process_runner, isolated_environment, "--version"), 0, stdout=f"platform-pki-backup {version}\n", stderr="")
    for arguments, message in (
        (("--unknown",), "invalid option: --unknown"),
        (("--backup-dir", ""), "must not be empty"),
        (("--namespace", tmp_path / "order", "--help"), "invalid option: --help"),
    ):
        result = run(process_runner, isolated_environment, *arguments)
        assert_result(result, 1, stdout="")
        assert message in result.stderr


@pytest.mark.parametrize("layout", ["legacy", "generation"])
def test_backup_rejects_partial_layout(tmp_path, process_runner, isolated_environment, layout) -> None:
    pki = tmp_path / f"partial-{layout}"
    leaf = pki / ("root-ca" if layout == "legacy" else "authorities/roots/g1")
    leaf.mkdir(mode=0o700, parents=True)
    for path in (pki, *leaf.parents):
        if path == tmp_path.parent:
            break
        if path.is_relative_to(pki):
            path.chmod(0o700)
    result = run(process_runner, isolated_environment, "--namespace", tmp_path / "namespace", "--pki-dir", pki, "--backup-dir", tmp_path / "backup", "--allow-plain-backup")
    assert result.status == 1
    assert "PKI backup refuses incomplete or ambiguous layout: partial" in result.stderr


def test_backup_age_recipient_argv_is_literal_and_archive_is_private(tmp_path, process_runner, isolated_environment, executable_directory) -> None:
    pki = tmp_path / "pki"
    create_legacy_pki(pki)
    write_private(
        pki / "state/csr/candidates/backup-test/0123456789abcdef0123456789abcdef/candidate",
        "schema=1\nstate=pending\n",
    )
    write_private(
        pki / "state/csr/replay/requests/0123456789abcdef0123456789abcdef",
        "schema=1\noutcome=reserved\n",
    )
    for directory in (path for path in (pki / "state").rglob("*") if path.is_dir()):
        directory.chmod(0o700)
    (pki / "state").chmod(0o700)
    fake_bin = executable_directory / "fake-bin"
    fake_age(fake_bin / "age")
    log = tmp_path / "age.log"
    log.touch()
    destination = tmp_path / "recipient-backups"
    literal = f"age1$(touch {tmp_path / 'injected'})"
    result = run(
        process_runner,
        environment(isolated_environment, PATH=f"{fake_bin}:{isolated_environment['PATH']}", AGE_LOG=os.fspath(log)),
        "--namespace", tmp_path / "namespace", "--pki-dir", pki, "--backup-dir", destination,
        "--age-recipient", "age1first", "--age-recipient", literal,
    )
    assert_result(result, 0)
    assert "[OK] Created encrypted PKI backup:" in result.stdout
    assert "PKI backup contains secrets" in result.stderr
    assert_age_argv(
        log,
        destination,
        ["-r", "age1first", "-r", literal, "-o"],
    )
    assert not (tmp_path / "injected").exists()
    archive = latest(destination, ".tar.gz.age")
    assert mode(archive) == 0o600
    listing = process_runner(["tar", "-tzf", archive], env=isolated_environment, timeout=10)
    assert_result(listing, 0, stderr="")
    assert "pki/private-state" in listing.stdout.splitlines()
    assert "pki/state/csr/candidates/backup-test/0123456789abcdef0123456789abcdef/candidate" in listing.stdout.splitlines()
    assert "pki/state/csr/replay/requests/0123456789abcdef0123456789abcdef" in listing.stdout.splitlines()
    archived_inventory = process_runner(
        ["tar", "-xOf", archive, "pki/inventory/services.yml"],
        env=isolated_environment,
        timeout=10,
    )
    assert_result(archived_inventory, 0, stderr="")
    assert "key_custody: host-local\n" in archived_inventory.stdout


def test_backup_age_passphrase_argv_and_plain_mode(tmp_path, process_runner, isolated_environment, executable_directory) -> None:
    pki = tmp_path / "pki"
    create_legacy_pki(pki)
    fake_bin = executable_directory / "fake-bin"
    fake_age(fake_bin / "age")
    log = tmp_path / "age.log"
    log.touch()
    encrypted = tmp_path / "passphrase-backups"
    result = run(process_runner, environment(isolated_environment, PATH=f"{fake_bin}:{isolated_environment['PATH']}", AGE_LOG=os.fspath(log)), "--namespace", tmp_path / "namespace", "--pki-dir", pki, "--backup-dir", encrypted)
    assert_result(result, 0)
    assert_age_argv(log, encrypted, ["-p", "-o"])
    assert mode(latest(encrypted, ".tar.gz.age")) == 0o600

    plain = tmp_path / "plain-backups"
    result = run(process_runner, isolated_environment, "--namespace", tmp_path / "namespace", "--pki-dir", pki, "--backup-dir", plain, "--allow-plain-backup")
    assert_result(result, 0)
    assert "Created unencrypted PKI backup" in result.stderr
    assert mode(latest(plain, ".tar.gz")) == 0o600


def test_backup_age_failure_removes_plaintext_and_encrypted_outputs(tmp_path, process_runner, isolated_environment, executable_directory) -> None:
    pki = tmp_path / "pki"
    create_legacy_pki(pki)
    fake_bin = executable_directory / "fake-bin"
    fake_age(fake_bin / "age")
    log = tmp_path / "age.log"
    log.touch()
    destination = tmp_path / "failure-backups"
    result = run(
        process_runner,
        environment(isolated_environment, PATH=f"{fake_bin}:{isolated_environment['PATH']}", AGE_LOG=os.fspath(log), AGE_FAIL="1"),
        "--namespace", tmp_path / "namespace", "--pki-dir", pki, "--backup-dir", destination, "--age-recipient", "age1failure",
    )
    assert_result(result, 1, stdout="")
    assert_age_argv(log, destination, ["-r", "age1failure", "-o"])
    assert not destination.exists() or not any(destination.iterdir())


def test_backup_publication_collision_preserves_foreign_file_and_uses_suffix(tmp_path, process_runner, isolated_environment, executable_directory) -> None:
    pki = tmp_path / "pki"
    create_legacy_pki(pki)
    fake_bin = executable_directory / "collision-bin"
    fake_age(fake_bin / "age")
    write_executable(fake_bin / "date", "#!/usr/bin/env bash\nprintf '%s\\n' '20260726-120000'\n")
    write_executable(fake_bin / "ln", """#!/usr/bin/env bash
set -euo pipefail
target=${!#}
if [[ ! -e $COLLISION_MARKER ]]; then
  printf '%s\\n' 'concurrent backup sentinel' >"$target"
  : >"$COLLISION_MARKER"
  exit 1
fi
exec "$REAL_LN" "$@"
""")
    destination = tmp_path / "collision-backups"
    destination.mkdir(mode=0o700)
    log = tmp_path / "age.log"
    log.touch()
    result = run(
        process_runner,
        environment(isolated_environment, PATH=f"{fake_bin}:{isolated_environment['PATH']}", AGE_LOG=os.fspath(log), COLLISION_MARKER=os.fspath(tmp_path / "marker"), REAL_LN=executable("ln")),
        "--namespace", tmp_path / "namespace", "--pki-dir", pki, "--backup-dir", destination, "--age-recipient", "age1collision",
    )
    assert_result(result, 0)
    assert (tmp_path / "marker").is_file()
    assert (destination / "platform-pki-20260726-120000.tar.gz.age").read_text() == "concurrent backup sentinel\n"
    published = destination / "platform-pki-20260726-120000-01.tar.gz.age"
    assert published.is_file() and mode(published) == 0o600
