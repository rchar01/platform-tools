from __future__ import annotations

import fcntl
import hashlib
import os
import re
from collections.abc import Callable, Mapping
from pathlib import Path

import pytest

from ..harness import ProcessResult
from src.platform_pki import backup as backup_module
from src.platform_pki.backup import BACKUP_RECEIPT_SPEC
from src.platform_pki.errors import ApplicationError
from src.platform_pki.parser import parse_route
from src.platform_pki.publication import PublicationAmbiguousError
from .support import BIN, REPOSITORY, assert_result, environment, executable_directory, mode, write_executable, write_private


pytestmark = pytest.mark.pki
TOOL = BIN / "platform-pki-backup"
UNIFIED = BIN / "platform-pki"
ORACLE = REPOSITORY / "tests/pki/oracles/platform-pki-backup/platform-pki-backup"
ORACLE_COMMIT = "3d5e3b4ecd4c137f97748b4066c7e4c508e99655"
ORACLE_SHA256 = "beac1204e2014e41be39254389ebc18a9db4b5a7b699197bf25187d5a8b6deea"
COMMON_SHA256 = "dee644be8ab6236cb368a553493f55b53a90c3aead291550f7e635c080a5494f"
PYTHON_INTERFACES = (
    pytest.param((TOOL,), id="compatibility"),
    pytest.param((UNIFIED, "backup"), id="unified"),
)


def run(process_runner: Callable[..., ProcessResult], env: Mapping[str, str], *arguments: object) -> ProcessResult:
    return process_runner([TOOL, *arguments], env=env, timeout=30)


def run_interface(
    process_runner: Callable[..., ProcessResult],
    env: Mapping[str, str],
    command: tuple[Path | str, ...],
    *arguments: object,
) -> ProcessResult:
    selected = dict(env)
    if command == (ORACLE,):
        selected["PLATFORM_TOOLS_LIB_DIR"] = os.fspath(
            REPOSITORY / "tests/pki/oracles/final-bash-source/lib"
        )
    return process_runner([*command, *arguments], env=selected, timeout=30)


def receipt_values(path: Path) -> dict[str, str]:
    data = path.read_bytes()
    record = BACKUP_RECEIPT_SPEC.parse(data)
    assert tuple(record) == BACKUP_RECEIPT_SPEC.fields
    return dict(record)


def create_legacy_pki(pki: Path) -> None:
    for directory in (pki / "inventory", pki / "root-ca", pki / "intermediate-ca"):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    pki.chmod(0o700)
    write_private(
        pki / "inventory/services.yml",
        "services:\n  backup-test:\n    key_custody: host-local\n"
        "    target: host-01\n"
        "    validation_boundary_sha256: 0000000000000000000000000000000000000000000000000000000000000000\n"
        "    rollback_hold_seconds: 3600\n"
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


def test_frozen_oracle_and_common_library_match_recorded_provenance() -> None:
    plan = (REPOSITORY / "docs/plans/platform-pki-python-migration.md").read_text(
        encoding="utf-8"
    )
    assert hashlib.sha256(ORACLE.read_bytes()).hexdigest() == ORACLE_SHA256
    assert hashlib.sha256(
        (REPOSITORY / "tests/pki/oracles/final-bash-source/lib/platform-pki-common.sh").read_bytes()
    ).hexdigest() == COMMON_SHA256
    assert ORACLE_COMMIT in plan
    assert os.access(ORACLE, os.X_OK)


def test_backup_compatibility_help_matches_frozen_oracle(
    process_runner, isolated_environment
) -> None:
    oracle = run_interface(process_runner, isolated_environment, (ORACLE,), "--help")
    result = run_interface(process_runner, isolated_environment, (TOOL,), "--help")
    assert result == ProcessResult(result.args, oracle.status, oracle.stdout, oracle.stderr)


@pytest.mark.parametrize("command", PYTHON_INTERFACES)
def test_plain_backup_receipt_and_manifest_match_frozen_oracle(
    tmp_path, process_runner, isolated_environment, command
) -> None:
    pki = tmp_path / "pki"
    create_legacy_pki(pki)
    (pki / "root-ca/private/nested").mkdir(mode=0o700, parents=True)
    write_private(
        pki / "root-ca/private/nested/root-ca.key",
        "private metadata sentinel\n",
    )
    (pki / "state/quarantine/nested").mkdir(mode=0o700, parents=True)
    (pki / "state").chmod(0o700)
    (pki / "state/quarantine").chmod(0o700)
    write_private(
        pki / "state/quarantine/nested/evidence",
        "quarantine metadata sentinel\n",
    )

    receipts_before = set((pki / "backups").glob("*.receipt"))
    oracle = run_interface(
        process_runner,
        isolated_environment,
        (ORACLE,),
        "--pki-dir",
        pki,
        "--allow-plain-backup",
    )
    assert_result(oracle, 0)
    oracle_receipt = (set((pki / "backups").glob("*.receipt")) - receipts_before).pop()
    oracle_archive = Path(os.fspath(oracle_receipt).removesuffix(".receipt"))

    receipts_before = set((pki / "backups").glob("*.receipt"))
    result = run_interface(
        process_runner,
        isolated_environment,
        command,
        "--pki-dir",
        pki,
        "--allow-plain-backup",
    )
    assert_result(result, 0)
    python_receipt = (set((pki / "backups").glob("*.receipt")) - receipts_before).pop()
    python_archive = Path(os.fspath(python_receipt).removesuffix(".receipt"))

    assert result.stdout.replace(os.fspath(python_archive), "<archive>") == (
        oracle.stdout.replace(os.fspath(oracle_archive), "<archive>")
    )
    assert result.stderr.replace(os.fspath(python_archive), "<archive>") == (
        oracle.stderr.replace(os.fspath(oracle_archive), "<archive>")
    )

    oracle_values = receipt_values(oracle_receipt)
    python_values = receipt_values(python_receipt)
    for archive, values in (
        (oracle_archive, oracle_values),
        (python_archive, python_values),
    ):
        metadata = archive.stat()
        assert values["layout"] == "legacy"
        assert re.fullmatch(r"[0-9a-f]{32}", values["session"])
        assert values["backup_path"] == os.fspath(archive)
        assert values["backup_device"] == str(metadata.st_dev)
        assert values["backup_inode"] == str(metadata.st_ino)
        assert values["backup_size"] == str(metadata.st_size)
        assert values["backup_mode"] == "600"
        assert values["backup_owner"] == str(metadata.st_uid)
        assert values["archive_sha256"] == hashlib.sha256(archive.read_bytes()).hexdigest()
        assert re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", values["created_at"])
        assert values["created_epoch"].isdigit()
    assert python_values["state_manifest_sha256"] == oracle_values["state_manifest_sha256"]
    assert python_values["private_metadata_sha256"] == oracle_values["private_metadata_sha256"]

    oracle_listing = process_runner(
        ["tar", "-tzf", oracle_archive], env=isolated_environment, timeout=10
    )
    python_listing = process_runner(
        ["tar", "-tzf", python_archive], env=isolated_environment, timeout=10
    )
    assert_result(oracle_listing, 0, stderr="")
    assert_result(python_listing, 0, stderr="")
    assert python_listing.stdout == oracle_listing.stdout

    custody = process_runner(
        [BIN / "platform-pki-custody-report", "--pki-dir", pki, "--format", "json"],
        env=isolated_environment,
        timeout=30,
    )
    assert custody.status in (0, 2)
    assert "invalid-backup-receipt" not in custody.stdout
    assert "missing-backup-receipt" not in custody.stdout


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


@pytest.mark.parametrize(
    ("lock_name", "label"),
    (
        ("lifecycle", "PKI lifecycle operation"),
        ("root", "root CA operation"),
        ("intermediate", "intermediate CA operation"),
        ("inventory", "inventory operation"),
        ("export", "export operation"),
    ),
)
def test_backup_acquires_full_operation_lock_profile(
    tmp_path, process_runner, isolated_environment, lock_name, label
) -> None:
    pki = tmp_path / f"lock-{lock_name}/pki"
    create_legacy_pki(pki)
    lock_path = pki / f"locks/{lock_name}"
    lock_path.parent.mkdir(mode=0o700)
    write_private(lock_path, "")
    destination = tmp_path / f"lock-{lock_name}/backups"

    with lock_path.open("r+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = run(
            process_runner,
            isolated_environment,
            "--pki-dir",
            pki,
            "--backup-dir",
            destination,
            "--allow-plain-backup",
        )

    assert result == ProcessResult(
        result.args,
        1,
        "",
        f"[ERROR] Another {label} is in progress: {lock_path}\n",
    )
    assert not any(destination.iterdir())


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
    destination = tmp_path / "collision-backups"
    destination.mkdir(mode=0o700)
    foreign = destination / "platform-pki-20260726-120000.tar.gz.age"
    foreign.write_text("concurrent backup sentinel\n")
    log = tmp_path / "age.log"
    log.touch()
    result = run(
        process_runner,
        environment(isolated_environment, PATH=f"{fake_bin}:{isolated_environment['PATH']}", AGE_LOG=os.fspath(log)),
        "--namespace", tmp_path / "namespace", "--pki-dir", pki, "--backup-dir", destination, "--age-recipient", "age1collision",
    )
    assert_result(result, 0)
    assert foreign.read_text() == "concurrent backup sentinel\n"
    published = destination / "platform-pki-20260726-120000-01.tar.gz.age"
    assert published.is_file() and mode(published) == 0o600


def test_receipt_collision_retains_published_archive_and_foreign_receipt(
    tmp_path, process_runner, isolated_environment, executable_directory
) -> None:
    pki = tmp_path / "pki"
    create_legacy_pki(pki)
    fake_bin = executable_directory / "receipt-collision-bin"
    write_executable(
        fake_bin / "date",
        "#!/usr/bin/env bash\nprintf '%s\\n' '20260726-130000'\n",
    )
    destination = tmp_path / "receipt-collision-backups"
    destination.mkdir(mode=0o700)
    archive = destination / "platform-pki-20260726-130000.tar.gz"
    receipt = Path(f"{archive}.receipt")
    write_private(receipt, "foreign receipt sentinel\n")

    result = run(
        process_runner,
        environment(
            isolated_environment,
            PATH=f"{fake_bin}:{isolated_environment['PATH']}",
        ),
        "--pki-dir",
        pki,
        "--backup-dir",
        destination,
        "--allow-plain-backup",
    )

    assert result.status == 1
    assert result.stdout == ""
    assert f"Backup receipt destination exists: {receipt}" in result.stderr
    assert f"must be retained for inspection: {archive}" in result.stderr
    assert archive.is_file() and mode(archive) == 0o600
    assert receipt.read_text() == "foreign receipt sentinel\n"
    assert not list(destination.glob(".platform-pki-backup.*"))


def _direct_backup_parse(pki: Path, destination: Path):
    return parse_route(
        ("backup",),
        (
            "--pki-dir",
            os.fspath(pki),
            "--backup-dir",
            os.fspath(destination),
            "--allow-plain-backup",
        ),
        interactive=False,
    )


def _set_direct_environment(
    monkeypatch: pytest.MonkeyPatch, isolated_environment: Mapping[str, str]
) -> None:
    for name, value in isolated_environment.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv(
        "PLATFORM_TOOLS_LIB_DIR",
        os.fspath(REPOSITORY / "tests/pki/oracles/final-bash-source/lib"),
    )


def test_receipt_publication_race_is_controlled_and_cleans_stage(
    tmp_path,
    isolated_environment,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    pki = tmp_path / "pki"
    destination = tmp_path / "receipt-race"
    create_legacy_pki(pki)
    _set_direct_environment(monkeypatch, isolated_environment)
    real_publish = backup_module.publish_no_clobber
    raced_receipt: Path | None = None

    def racing_publish(*args, **kwargs):
        nonlocal raced_receipt
        destination_parent = args[3]
        destination_name = args[4]
        if destination_name.endswith(".receipt"):
            raced_receipt = destination / destination_name
            descriptor = os.open(
                destination_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                0o600,
                dir_fd=destination_parent.fileno(),
            )
            with os.fdopen(descriptor, "w", encoding="ascii") as stream:
                stream.write("foreign receipt sentinel\n")
        return real_publish(*args, **kwargs)

    monkeypatch.setattr(backup_module, "publish_no_clobber", racing_publish)
    with pytest.raises(ApplicationError, match="Backup receipt destination exists"):
        backup_module.backup(_direct_backup_parse(pki, destination))

    captured = capsys.readouterr()
    assert "published without a receipt" in captured.err
    assert raced_receipt is not None
    assert raced_receipt.read_text(encoding="ascii") == "foreign receipt sentinel\n"
    assert len(list(destination.glob("platform-pki-*.tar.gz"))) == 1
    assert not list(destination.glob(".*.receipt.stage-*"))
    assert not list(destination.glob(".platform-pki-backup.*"))


def test_archive_replacement_during_receipt_publication_prevents_success(
    tmp_path,
    isolated_environment,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    pki = tmp_path / "pki"
    destination = tmp_path / "archive-race"
    create_legacy_pki(pki)
    _set_direct_environment(monkeypatch, isolated_environment)
    real_publish = backup_module.publish_no_clobber
    replacement = b"foreign archive replacement\n"

    def racing_publish(*args, **kwargs):
        destination_parent = args[3]
        destination_name = args[4]
        if destination_name.endswith(".receipt"):
            archive_name = destination_name.removesuffix(".receipt")
            os.unlink(archive_name, dir_fd=destination_parent.fileno())
            descriptor = os.open(
                archive_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                0o600,
                dir_fd=destination_parent.fileno(),
            )
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(replacement)
        return real_publish(*args, **kwargs)

    monkeypatch.setattr(backup_module, "publish_no_clobber", racing_publish)
    with pytest.raises(
        ApplicationError,
        match="Published PKI backup or receipt identity changed",
    ):
        backup_module.backup(_direct_backup_parse(pki, destination))

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "archive and receipt publication must be retained" in captured.err
    archive = next(destination.glob("platform-pki-*.tar.gz"))
    assert archive.read_bytes() == replacement
    assert Path(f"{archive}.receipt").is_file()
    assert not list(destination.glob(".*.receipt.stage-*"))


def test_ambiguous_receipt_publication_reports_uncertain_evidence(
    tmp_path,
    isolated_environment,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    pki = tmp_path / "pki"
    destination = tmp_path / "ambiguous-receipt"
    create_legacy_pki(pki)
    _set_direct_environment(monkeypatch, isolated_environment)
    real_publish = backup_module.publish_no_clobber

    def ambiguous_publish(*args, **kwargs):
        result = real_publish(*args, **kwargs)
        if args[4].endswith(".receipt"):
            raise PublicationAmbiguousError()
        return result

    monkeypatch.setattr(backup_module, "publish_no_clobber", ambiguous_publish)
    with pytest.raises(
        ApplicationError,
        match="Backup receipt publication requires inspection",
    ):
        backup_module.backup(_direct_backup_parse(pki, destination))

    captured = capsys.readouterr()
    assert "published without a receipt" not in captured.err
    assert "receipt publication is uncertain" in captured.err
    archive = next(destination.glob("platform-pki-*.tar.gz"))
    assert Path(f"{archive}.receipt").is_file()
