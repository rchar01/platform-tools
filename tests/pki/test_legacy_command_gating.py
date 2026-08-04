from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

import pytest

from ..harness import ProcessResult
from .support import BIN, mode, write_private


pytestmark = pytest.mark.pki
MIGRATION_ERROR = (
    "[ERROR] Legacy PKI state requires migration; create a fresh backup and "
    "follow platform-pki-ca-rollover status/migrate\n"
)


def create_legacy_pki(pki: Path) -> None:
    for directory in (
        pki / "inventory",
        pki / "root-ca",
        pki / "intermediate-ca",
        pki / "services",
        pki / "export",
    ):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    pki.chmod(0o700)
    write_private(
        pki / "inventory/services.yml",
        "services:\n  legacy-service:\n    common_name: legacy.example.internal\n"
        "    dns:\n      - legacy.example.internal\n",
    )
    write_private(pki / "root-ca/sentinel", "legacy root\n")
    write_private(pki / "intermediate-ca/sentinel", "legacy intermediate\n")


@pytest.mark.parametrize(
    ("tool", "arguments", "locks"),
    (
        pytest.param("platform-pki-list-expiry", (), ("lifecycle", "root", "intermediate", "inventory"), id="list-expiry"),
        pytest.param("platform-pki-print-cert", ("legacy-service",), ("lifecycle", "root", "intermediate", "inventory"), id="print-cert"),
        pytest.param("platform-pki-service-verify", ("legacy-service",), ("lifecycle", "root", "intermediate", "inventory"), id="service-verify"),
        pytest.param("platform-pki-service-issue", ("legacy-service",), ("lifecycle", "root", "intermediate", "inventory"), id="service-issue"),
        pytest.param("platform-pki-service-renew", ("legacy-service",), ("lifecycle", "root", "intermediate", "inventory"), id="service-renew"),
        pytest.param("platform-pki-export-ansible", (), ("lifecycle", "root", "intermediate", "inventory", "export"), id="export-ansible"),
        pytest.param("platform-pki-root-create", ("--name", "Test Root", "--org", "Test", "--country", "PL", "--allow-unencrypted-root-key"), ("lifecycle", "root"), id="root-create"),
        pytest.param("platform-pki-intermediate-create", ("--name", "Test Intermediate", "--org", "Test", "--country", "PL", "--allow-unencrypted-intermediate-key"), ("lifecycle", "root", "intermediate"), id="intermediate-create"),
    ),
)
def test_legacy_commands_prepare_control_state_and_require_migration(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    isolated_environment: Mapping[str, str],
    tool: str,
    arguments: Sequence[str],
    locks: Sequence[str],
) -> None:
    pki = tmp_path / tool
    create_legacy_pki(pki)

    result = process_runner(
        [BIN / tool, *arguments, "--pki-dir", pki],
        env=isolated_environment,
        timeout=30,
    )

    assert result.status == 1
    assert result.stdout == ""
    assert result.stderr == MIGRATION_ERROR
    for directory in (
        pki / "locks",
        pki / "state",
        pki / "state/rollover",
        pki / "state/rollovers",
        pki / "state/generation-reservations",
    ):
        assert directory.is_dir() and not directory.is_symlink()
        assert mode(directory) == 0o700
    assert {path.name for path in (pki / "locks").iterdir()} == set(locks)
    assert all(mode(pki / "locks" / name) == 0o600 for name in locks)
    assert (pki / "root-ca/sentinel").read_text() == "legacy root\n"
    assert (pki / "intermediate-ca/sentinel").read_text() == "legacy intermediate\n"
    assert not (pki / "authorities").exists()


def test_root_create_rejects_mixed_legacy_and_generation_state(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    isolated_environment: Mapping[str, str],
) -> None:
    pki = tmp_path / "mixed"
    create_legacy_pki(pki)
    (pki / "authorities/roots/g1").mkdir(mode=0o700, parents=True)

    result = process_runner(
        [
            BIN / "platform-pki-root-create",
            "--pki-dir",
            pki,
            "--name",
            "Test Root",
            "--org",
            "Test",
            "--country",
            "PL",
            "--allow-unencrypted-root-key",
        ],
        env=isolated_environment,
        timeout=30,
    )

    assert result.status == 1
    assert result.stdout == ""
    assert result.stderr == "[ERROR] PKI state is incomplete or ambiguous; run platform-pki-ca-rollover status\n"
    assert not (pki / "state/active-issuer").exists()
    assert list((pki / "authorities/roots").iterdir()) == [pki / "authorities/roots/g1"]


@pytest.mark.parametrize("authority_kind", ("directory", "dangling-symlink"))
def test_root_create_rejects_partial_generation_or_legacy_state(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    isolated_environment: Mapping[str, str],
    authority_kind: str,
) -> None:
    pki = tmp_path / authority_kind
    pki.mkdir(mode=0o700)
    if authority_kind == "directory":
        generation = pki / "authorities/roots/g1"
        generation.mkdir(mode=0o700, parents=True)
        write_private(generation / "sentinel", "partial generation\n")
    else:
        (pki / "root-ca").symlink_to(pki / "missing-legacy-root")

    result = process_runner(
        [
            BIN / "platform-pki-root-create",
            "--pki-dir",
            pki,
            "--name",
            "Test Root",
            "--org",
            "Test",
            "--country",
            "PL",
            "--allow-unencrypted-root-key",
        ],
        env=isolated_environment,
        timeout=30,
    )

    assert result.status == 1
    assert result.stdout == ""
    assert result.stderr == "[ERROR] PKI state is incomplete or ambiguous; run platform-pki-ca-rollover status\n"
    assert not (pki / "state/active-issuer").exists()
    if authority_kind == "directory":
        assert (pki / "authorities/roots/g1/sentinel").read_text() == "partial generation\n"
        assert {path.name for path in (pki / "authorities/roots").iterdir()} == {"g1"}
    else:
        assert (pki / "root-ca").is_symlink()
        assert (pki / "root-ca").readlink() == pki / "missing-legacy-root"


@pytest.mark.parametrize(
    ("relative_path", "object_kind"),
    (
        pytest.param("authorities/roots/unexpected", "directory", id="malformed-root-directory"),
        pytest.param("authorities/roots/orphan", "file", id="orphan-root-file"),
        pytest.param("authorities/roots/.staging", "file", id="hidden-root-file"),
        pytest.param("authorities/intermediates/unexpected", "directory", id="malformed-intermediate-directory"),
        pytest.param("authorities/intermediates/orphan", "dangling-symlink", id="orphan-intermediate-symlink"),
        pytest.param("authorities/roots", "file", id="invalid-root-container"),
    ),
)
def test_root_create_rejects_unexpected_authority_tree_entries(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    isolated_environment: Mapping[str, str],
    relative_path: str,
    object_kind: str,
) -> None:
    pki = tmp_path / "unexpected-authority"
    pki.mkdir(mode=0o700)
    unexpected = pki / relative_path
    unexpected.parent.mkdir(mode=0o700, parents=True)
    if object_kind == "directory":
        unexpected.mkdir(mode=0o700)
    elif object_kind == "file":
        write_private(unexpected, "unexpected authority state\n")
    else:
        unexpected.symlink_to(pki / "missing-authority-state")

    result = process_runner(
        [
            BIN / "platform-pki-root-create",
            "--pki-dir",
            pki,
            "--name",
            "Test Root",
            "--org",
            "Test",
            "--country",
            "PL",
            "--allow-unencrypted-root-key",
        ],
        env=isolated_environment,
        timeout=30,
    )

    assert result.status == 1
    assert result.stdout == ""
    assert result.stderr == "[ERROR] PKI state is incomplete or ambiguous; run platform-pki-ca-rollover status\n"
    assert not (pki / "state/active-issuer").exists()
    if object_kind == "directory":
        assert unexpected.is_dir() and not unexpected.is_symlink()
    elif object_kind == "file":
        assert unexpected.read_text() == "unexpected authority state\n"
    else:
        assert unexpected.is_symlink()
        assert unexpected.readlink() == pki / "missing-authority-state"


def test_legacy_gate_prioritizes_recovery_state(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    isolated_environment: Mapping[str, str],
) -> None:
    pki = tmp_path / "recovery"
    create_legacy_pki(pki)
    marker = pki / "state/rollover/recovery-required"
    for directory in (pki / "state", pki / "state/rollover"):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        directory.chmod(0o700)
    write_private(marker, "transaction=legacy-migrate-test\n")

    result = process_runner(
        [BIN / "platform-pki-list-expiry", "--pki-dir", pki],
        env=isolated_environment,
        timeout=30,
    )

    assert result.status == 1
    assert result.stdout == ""
    assert result.stderr == f"[ERROR] PKI recovery is required before this command can continue: {marker}\n"


def test_concurrent_legacy_control_state_preparation_is_idempotent(
    tmp_path: Path,
    process_runner: Callable[..., ProcessResult],
    isolated_environment: Mapping[str, str],
) -> None:
    pki = tmp_path / "concurrent"
    create_legacy_pki(pki)

    def invoke() -> ProcessResult:
        return process_runner(
            [BIN / "platform-pki-list-expiry", "--pki-dir", pki],
            env=isolated_environment,
            timeout=30,
        )

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = tuple(executor.map(lambda _index: invoke(), range(8)))

    assert all(result.status == 1 and result.stdout == "" for result in results)
    assert all("Cannot create PKI control directory" not in result.stderr for result in results)
    assert all(
        result.stderr == MIGRATION_ERROR
        or result.stderr.startswith("[ERROR] Another PKI lifecycle operation is in progress:")
        for result in results
    )
    for directory in ("locks", "state", "state/rollover", "state/rollovers", "state/generation-reservations"):
        assert (pki / directory).is_dir() and mode(pki / directory) == 0o700
