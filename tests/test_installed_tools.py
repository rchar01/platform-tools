from __future__ import annotations

import json
import os
import re
import shutil
import stat
import tempfile
from collections.abc import Callable, Generator
from dataclasses import dataclass
from pathlib import Path

import pytest

from .harness import ProcessResult, run_process
ROOT = Path(__file__).resolve().parents[1]
VERSION = (ROOT / "VERSION").read_text().strip()


def make_inventory(name: str) -> tuple[str, ...]:
    rule = f".PHONY: pytest-print-{name}\npytest-print-{name}:\n\t@printf '%s\\n' '$({name})'\n"
    result = run_process(
        (
            "make",
            "-s",
            "--no-print-directory",
            "-f",
            "Makefile",
            "-f",
            "-",
            f"pytest-print-{name}",
        ),
        cwd=ROOT,
        input=rule,
        timeout=30,
    )
    if result.status != 0 or result.stderr:
        raise RuntimeError(
            f"failed to query Make inventory: status={result.status}, stderr={result.stderr!r}"
        )
    entries = tuple(result.stdout.split())
    if not entries:
        raise RuntimeError(f"Make variable {name} must not be empty")
    if len(entries) != len(set(entries)):
        raise RuntimeError(f"Make variable {name} contains duplicates")
    return entries


TOOLS = make_inventory("TOOLS")
PYTHON_ZIPAPPS = make_inventory("PYTHON_ZIPAPPS")
LEGACY_PKI_ALIASES = make_inventory("LEGACY_PKI_ALIASES")
EXPECTED_LEGACY_PKI_ALIASES = (
    "platform-pki-init",
    "platform-pki-inventory-install",
    "platform-pki-print-cert",
    "platform-pki-list-expiry",
    "platform-pki-service-verify",
    "platform-pki-export-ansible",
    "platform-pki-backup",
    "platform-pki-custody-report",
    "platform-pki-ca-passphrase-verify",
    "platform-pki-root-create",
    "platform-pki-intermediate-create",
    "platform-pki-csr-recover",
    "platform-pki-service-issue",
    "platform-pki-service-renew",
    "platform-pki-csr-trust-install",
    "platform-pki-certificate-export",
    "platform-pki-csr-candidate",
    "platform-pki-ca-rollover",
)
RETIRED_SHELL_LIBRARIES = (
    "platform-pki-common.sh",
    "platform-pki-csr-sign.sh",
    "platform-pki-csr-candidate.sh",
)
DEPENDENCIES = (
    "bash",
    "python3",
    "dirname",
    "mkdir",
    "chmod",
    "id",
    "stat",
    "find",
    "mktemp",
    "cp",
    "mv",
    "rm",
    "ln",
    "pwd",
    "flock",
    "date",
    "gzip",
    "openssl",
    "ssh-keygen",
    "tar",
    "cmp",
)
LEGACY_MIGRATION_ERROR = (
    "[ERROR] Legacy PKI state requires migration; create a fresh backup and "
    "follow platform-pki ca-rollover status/migrate\n"
)


def require_outside_checkout(path: Path, label: str, *, strict: bool = False) -> Path:
    if not path.is_absolute():
        raise ValueError(f"{label} must be absolute: {path}")
    resolved = path.resolve(strict=strict)
    if resolved.is_relative_to(ROOT):
        raise ValueError(f"{label} resolves inside the checkout: {resolved}")
    return resolved


def state_parent_from_environment() -> Path:
    configured = os.environ.get("XDG_CACHE_HOME")
    path = Path(configured) if configured is not None else Path.home() / ".cache"
    return require_outside_checkout(path, "XDG_CACHE_HOME")


@dataclass(frozen=True)
class Install:
    staged_bin: Path
    staged_share: Path
    install_bin: Path
    share: Path
    runtime: Path
    home: Path
    config: Path
    data: Path
    state: Path

    def clean_argv(self, *args: str | Path) -> tuple[str, ...]:
        return (
            "/usr/bin/env",
            "-i",
            f"HOME={self.home}",
            f"XDG_CONFIG_HOME={self.config}",
            f"XDG_DATA_HOME={self.data}",
            f"PATH={self.runtime}",
            *(os.fspath(arg) for arg in args),
        )


@pytest.fixture(scope="module")
def install() -> Generator[Install, None, None]:
    staged_parent = ROOT / ".tmp"
    staged_parent.mkdir(exist_ok=True)
    staged_base = Path(tempfile.mkdtemp(prefix="pytest-installed-staged.", dir=staged_parent))
    state_parent = state_parent_from_environment()
    state_parent.mkdir(parents=True, exist_ok=True)
    base = Path(tempfile.mkdtemp(prefix="platform-tools-pytest-installed.", dir=state_parent))
    value = Install(
        staged_bin=staged_base / "install/bin",
        staged_share=staged_base / "install/share/platform-tools",
        install_bin=base / "install/bin",
        share=base / "xdg-data/platform-tools",
        runtime=base / "runtime-bin",
        home=base / "home",
        config=base / "xdg-config",
        data=base / "xdg-data",
        state=base,
    )
    make = shutil.which("make")
    assert make is not None
    for install_dir, share_dir in (
        (value.staged_bin, value.staged_share),
        (value.install_bin, value.share),
    ):
        result = run_process(
            (
                "/usr/bin/env",
                "-i",
                f"HOME={Path.home()}",
                f"PATH={os.environ['PATH']}",
                make,
                "-C",
                os.fspath(ROOT),
                "install",
                f"INSTALL_DIR={install_dir}",
                f"SHARE_DIR={share_dir}",
            ),
            cwd=ROOT,
            env=os.environ,
            timeout=60,
        )
        assert result.status == 0, result.stderr
        assert result.stdout
        assert f"Installed shared assets to {share_dir}\n" in result.stdout
        assert result.stderr == ""
    value.runtime.mkdir()
    value.home.mkdir()
    value.config.mkdir()
    for command in DEPENDENCIES:
        source = shutil.which(command)
        assert source is not None, f"required smoke dependency not found: {command}"
        (value.runtime / command).symlink_to(source)
    for tool in TOOLS:
        (value.runtime / tool).symlink_to(value.install_bin / tool)
    try:
        yield value
    finally:
        shutil.rmtree(staged_base)
        shutil.rmtree(base)


def execute(
    process_runner: Callable[..., ProcessResult], install: Install, *args: str | Path
) -> ProcessResult:
    return process_runner(install.clean_argv(*args), cwd=install.state, env={})


def assert_success_stdout(result: ProcessResult) -> None:
    assert result.status == 0, result.stderr
    assert result.stdout
    assert result.stderr == ""


@pytest.mark.parametrize("tool", TOOLS, ids=TOOLS)
def test_staged_and_installed_commands_exist(install: Install, tool: str) -> None:
    staged = install.staged_bin / tool
    installed = install.install_bin / tool
    runtime = install.runtime / tool
    assert staged.is_file()
    assert installed.is_file()
    assert not staged.is_symlink()
    assert not installed.is_symlink()
    assert os.access(staged, os.X_OK)
    assert os.access(installed, os.X_OK)
    assert runtime.is_symlink()
    assert runtime.resolve(strict=True) == installed.resolve(strict=True)


def test_clean_install_inventory_is_unified_only(install: Install) -> None:
    assert PYTHON_ZIPAPPS == ("platform-pki",)
    assert LEGACY_PKI_ALIASES == EXPECTED_LEGACY_PKI_ALIASES
    for install_bin in (install.staged_bin, install.install_bin):
        assert {entry.name for entry in install_bin.iterdir()} == set(TOOLS)
        assert not any((install_bin / alias).is_symlink() for alias in LEGACY_PKI_ALIASES)


@pytest.mark.parametrize(
    "stale_kind", ("regular", "directory", "dangling-symlink", "live-symlink")
)
def test_install_rejects_legacy_alias_before_mutation(
    process_runner: Callable[..., ProcessResult], tmp_path: Path, stale_kind: str
) -> None:
    install_dir = tmp_path / "custom bin"
    install_dir.mkdir()
    sentinel = install_dir / "sentinel"
    sentinel.write_bytes(b"preserve sentinel\n")
    sentinel.chmod(0o640)
    alias = install_dir / LEGACY_PKI_ALIASES[0]
    if stale_kind == "regular":
        alias.write_bytes(b"preserve legacy file\n")
        alias.chmod(0o600)
    elif stale_kind == "directory":
        alias.mkdir()
        alias.chmod(0o750)
        (alias / "preserve").write_bytes(b"preserve legacy directory\n")
    elif stale_kind == "dangling-symlink":
        alias.symlink_to("missing-legacy-target")
    else:
        target = tmp_path / "live legacy target"
        target.write_bytes(b"preserve live target\n")
        target.chmod(0o600)
        alias.symlink_to(target)
    share_dir = tmp_path / "absent share"

    result = process_runner(
        (
            "make",
            "-s",
            "--no-print-directory",
            "install",
            f"INSTALL_DIR={install_dir}",
            f"SHARE_DIR={share_dir}",
        ),
        cwd=ROOT,
        env=os.environ,
    )

    assert result.status != 0
    assert result.stdout == ""
    assert result.stderr.startswith(
        "platform-tools v3 install blocked by legacy PKI aliases:\n"
        f"  {alias}\n"
        "Remove or relocate the listed paths, then rerun make install.\n"
        "v3 installs only platform-pki for PKI.\n"
    )
    assert {entry.name for entry in install_dir.iterdir()} == {"sentinel", alias.name}
    assert sentinel.read_bytes() == b"preserve sentinel\n"
    assert sentinel.stat().st_mode & 0o777 == 0o640
    if stale_kind == "regular":
        assert alias.read_bytes() == b"preserve legacy file\n"
        assert alias.stat().st_mode & 0o777 == 0o600
    elif stale_kind == "directory":
        assert alias.is_dir()
        assert alias.stat().st_mode & 0o777 == 0o750
        assert (alias / "preserve").read_bytes() == b"preserve legacy directory\n"
    elif stale_kind == "dangling-symlink":
        assert alias.is_symlink()
        assert os.readlink(alias) == "missing-legacy-target"
    else:
        target = tmp_path / "live legacy target"
        assert alias.is_symlink()
        assert os.readlink(alias) == os.fspath(target)
        assert target.read_bytes() == b"preserve live target\n"
        assert target.stat().st_mode & 0o777 == 0o600
    assert not share_dir.exists()
    assert not share_dir.is_symlink()


def test_installed_assets_exclude_retired_shell_libraries(install: Install) -> None:
    for share in (install.staged_share, install.share):
        for name in RETIRED_SHELL_LIBRARIES:
            library = share / "lib" / name
            assert not library.exists()
            assert not library.is_symlink()
        template = share / "templates/pki/services.yml.example"
        assert template.is_file()
        assert not template.is_symlink()


@pytest.mark.parametrize("tool", TOOLS, ids=TOOLS)
@pytest.mark.parametrize("flag", ("--help", "-h"), ids=("long", "short"))
def test_installed_help(
    process_runner: Callable[..., ProcessResult], install: Install, tool: str, flag: str
) -> None:
    assert_success_stdout(execute(process_runner, install, install.runtime / tool, flag))


@pytest.mark.parametrize("tool", TOOLS, ids=TOOLS)
@pytest.mark.parametrize("flag", ("--version", "-v"), ids=("long", "short"))
def test_installed_version(
    process_runner: Callable[..., ProcessResult], install: Install, tool: str, flag: str
) -> None:
    result = execute(process_runner, install, install.runtime / tool, flag)
    assert_success_stdout(result)
    assert result.stdout == f"{tool} {VERSION}\n"


@pytest.mark.parametrize("tool", TOOLS, ids=TOOLS)
def test_installed_parser_error(
    process_runner: Callable[..., ProcessResult], install: Install, tool: str
) -> None:
    result = execute(process_runner, install, install.runtime / tool, "--contract-invalid-option")
    assert result.status == 1
    assert result.stdout == ""
    assert result.stderr


def test_runtime_is_outside_checkout_and_has_minimal_path(install: Install) -> None:
    for path in (
        install.runtime,
        install.install_bin,
        install.share,
        install.home,
        install.config,
        install.data,
        install.state,
    ):
        assert require_outside_checkout(path, "installed path", strict=True) == path.resolve()
    assert Path.cwd().resolve() != install.state.resolve()
    for unexpected in (install.runtime / "ruby", install.runtime / "bashly"):
        assert not unexpected.exists()
        assert not unexpected.is_symlink()
    for name in RETIRED_SHELL_LIBRARIES:
        adjacent_library = install.install_bin.parent / "lib" / name
        assert not adjacent_library.exists()
        assert not adjacent_library.is_symlink()


def test_relative_xdg_cache_home_is_rejected(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("XDG_CACHE_HOME", "relative-cache")
    with pytest.raises(ValueError, match="XDG_CACHE_HOME must be absolute"):
        state_parent_from_environment()
    assert not (tmp_path / "relative-cache").exists()


def test_installed_pki_shared_asset_lookup(
    process_runner: Callable[..., ProcessResult],
    install: Install,
) -> None:
    namespace = install.state / "pki-namespace"
    result = execute(
        process_runner,
        install,
        install.runtime / "platform-pki",
        "init",
        "--namespace",
        namespace,
    )
    assert result.status == 0, result.stderr
    assert result.stderr == ""
    example = namespace / "pki/inventory/services.yml.example"
    installed_template = install.share / "templates/pki/services.yml.example"
    assert example.is_file()
    assert not example.is_symlink()
    active_inventory = namespace / "pki/inventory/services.yml"
    assert not active_inventory.exists()
    assert not active_inventory.is_symlink()
    assert not installed_template.is_symlink()
    require_outside_checkout(example, "initialized PKI template", strict=True)
    require_outside_checkout(installed_template, "installed PKI template", strict=True)
    assert example.read_bytes() == installed_template.read_bytes()


def test_installed_root_create_operates_outside_checkout(
    process_runner: Callable[..., ProcessResult],
    install: Install,
) -> None:
    namespace = install.state / "root-create-namespace"
    initialized = execute(
        process_runner,
        install,
        install.runtime / "platform-pki",
        "init",
        "--namespace",
        namespace,
    )
    assert initialized.status == 0, initialized.stderr

    result = execute(
        process_runner,
        install,
        install.runtime / "platform-pki",
        "root-create",
        "--namespace",
        namespace,
        "--name",
        "Installed Root",
        "--org",
        "Platform Test",
        "--country",
        "PL",
        "--allow-unencrypted-root-key",
    )

    pki = namespace / "pki"
    authority = pki / "authorities/roots/g1"
    key = authority / "private/root-ca.key"
    certificate = authority / "certs/root-ca.crt"
    bootstrap = pki / "state/bootstrap-root"
    reservation = pki / "state/generation-reservations/g1"
    assert result.status == 0, result.stderr
    assert result.stdout == (
        f"[OK] Created root CA generation g1: {certificate}\n"
    )
    assert result.stderr == (
        "[WARN] Creating an unencrypted root CA private key because "
        "--allow-unencrypted-root-key was used\n"
    )
    for path, expected_mode in (
        (key, 0o600),
        (certificate, 0o644),
        (bootstrap, 0o600),
        (reservation, 0o600),
    ):
        assert path.is_file() and not path.is_symlink()
        assert stat.S_IMODE(path.stat().st_mode) == expected_mode
        require_outside_checkout(path, "installed root artifact", strict=True)
    bootstrap_record = dict(
        line.split("=", 1) for line in bootstrap.read_text().splitlines()
    )
    reservation_record = dict(
        line.split("=", 1) for line in reservation.read_text().splitlines()
    )
    assert bootstrap_record["root"] == "g1"
    assert reservation_record == {
        "generation": "g1",
        "kind": "root",
        "status": "consumed",
        "fingerprint_sha256": bootstrap_record["fingerprint_sha256"],
        "transaction": reservation_record["transaction"],
    }
    assert re.fullmatch(r"[0-9A-F]{64}", bootstrap_record["fingerprint_sha256"])
    assert re.fullmatch(
        r"root-bootstrap-[0-9]{8}-[0-9]{6}-[0-9]+",
        reservation_record["transaction"],
    )
    for arguments in (
        ("x509", "-in", certificate, "-noout"),
        ("pkey", "-in", key, "-noout"),
    ):
        verified = execute(
            process_runner,
            install,
            install.runtime / "openssl",
            *arguments,
        )
        assert verified.status == 0, verified.stderr


def test_installed_intermediate_create_operates_outside_checkout(
    process_runner: Callable[..., ProcessResult],
    install: Install,
) -> None:
    namespace = install.state / "intermediate-create-namespace"
    initialized = execute(
        process_runner,
        install,
        install.runtime / "platform-pki",
        "init",
        "--namespace",
        namespace,
    )
    assert initialized.status == 0, initialized.stderr
    root = execute(
        process_runner,
        install,
        install.runtime / "platform-pki",
        "root-create",
        "--namespace",
        namespace,
        "--name",
        "Installed Root",
        "--org",
        "Platform Test",
        "--country",
        "PL",
        "--allow-unencrypted-root-key",
    )
    assert root.status == 0, root.stderr

    result = execute(
        process_runner,
        install,
        install.runtime / "platform-pki",
        "intermediate-create",
        "--namespace",
        namespace,
        "--name",
        "Installed Intermediate",
        "--org",
        "Platform Test",
        "--country",
        "PL",
        "--allow-unencrypted-intermediate-key",
    )

    pki = namespace / "pki"
    authority = pki / "authorities/intermediates/g1-i1"
    certificate = authority / "certs/intermediate-ca.crt"
    assert result.status == 0, result.stderr
    assert result.stdout == (
        f"[OK] Created intermediate CA generation g1-i1: {certificate}\n"
    )
    assert result.stderr.startswith(
        "[WARN] Creating an unencrypted intermediate CA private key because "
        "--allow-unencrypted-intermediate-key was used\n"
    )
    assert "Database updated\n" in result.stderr
    assert (pki / "state/active-issuer").read_bytes() == (
        b"root=g1\nintermediate=g1-i1\n"
    )
    assert not (pki / "state/bootstrap-root").exists()
    for path, expected_mode in (
        (authority / "private/intermediate-ca.key", 0o600),
        (certificate, 0o644),
        (authority / "certs/ca-chain.crt", 0o644),
        (pki / "state/generation-reservations/g1-i1", 0o600),
    ):
        assert path.is_file() and not path.is_symlink()
        assert stat.S_IMODE(path.stat().st_mode) == expected_mode
        require_outside_checkout(path, "installed intermediate artifact", strict=True)


def test_installed_inventory_install_operates_without_shell_libraries(
    process_runner: Callable[..., ProcessResult],
    install: Install,
) -> None:
    namespace = install.state / "inventory-namespace"
    private = install.state / "inventory-private"
    (private / "pki").mkdir(mode=0o700, parents=True)
    private.chmod(0o700)
    source = private / "pki/services.yml"
    source.write_text(
        "services:\n  api:\n    common_name: api.example\n    dns:\n      - api.example\n",
        encoding="utf-8",
    )
    source.chmod(0o600)
    initialized = execute(
        process_runner,
        install,
        install.runtime / "platform-pki",
        "init",
        "--namespace",
        namespace,
    )
    assert initialized.status == 0, initialized.stderr

    result = execute(
        process_runner,
        install,
        install.runtime / "platform-pki",
        "inventory-install",
        "--namespace",
        namespace,
        "--private-repo",
        private,
    )
    assert result.status == 0, result.stderr
    assert result.stderr == ""
    destination = namespace / "pki/inventory/services.yml"
    assert destination.read_bytes() == source.read_bytes()
    assert destination.stat().st_mode & 0o777 == 0o600


def test_installed_custody_report_operates_without_shell_libraries(
    process_runner: Callable[..., ProcessResult],
    install: Install,
) -> None:
    pki = install.state / "custody-pki"
    for directory in (
        pki / "authorities/roots/g1/private",
        pki / "authorities/intermediates/g1-i1/private",
        pki / "state",
        pki / "locks",
    ):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    for directory in (pki, *(path for path in pki.rglob("*") if path.is_dir())):
        directory.chmod(0o700)
    files = {
        pki / "state/active-issuer": b"root=g1\nintermediate=g1-i1\n",
        pki / "authorities/roots/g1/private/root-ca.key": (
            b"-----BEGIN ENCRYPTED " b"PRIVATE KEY-----\nprivate-root-tail\n"
        ),
        pki / "authorities/intermediates/g1-i1/private/intermediate-ca.key": (
            b"-----BEGIN ENCRYPTED " b"PRIVATE KEY-----\nprivate-intermediate-tail\n"
        ),
    }
    for path, data in files.items():
        path.write_bytes(data)
        path.chmod(0o600)

    result = execute(
        process_runner,
        install,
        install.runtime / "platform-pki",
        "custody-report",
        "--pki-dir",
        pki,
        "--format",
        "json",
    )

    assert result.status == 0, result.stderr
    assert result.stderr == ""
    report = json.loads(result.stdout)
    assert report["status"] == "ok"
    assert report["layout"] == "generation"
    assert report["storage_encryption_evidence"] == "unknown"
    assert "private-root-tail" not in result.stdout


def test_installed_ca_passphrase_verify_operates_without_shell_libraries(
    process_runner: Callable[..., ProcessResult],
    install: Install,
) -> None:
    passphrase = install.state / "passphrase"
    passphrase.write_text("installed-passphrase-value\n", encoding="utf-8")
    passphrase.chmod(0o600)
    pki = install.state / "missing-passphrase-pki"

    result = execute(
        process_runner,
        install,
        install.runtime / "platform-pki",
        "ca-passphrase-verify",
        "--pki-dir",
        pki,
        "--root-pass-file",
        passphrase,
    )

    assert result.status == 1
    assert result.stdout == ""
    assert result.stderr == (
        "[ERROR] PKI directory does not exist; run platform-pki init first: "
        f"{pki}\n"
    )


def test_installed_backup_operates_without_shell_libraries(
    process_runner: Callable[..., ProcessResult],
    install: Install,
) -> None:
    pki = install.state / "backup-pki"
    for directory in (pki / "inventory", pki / "root-ca", pki / "intermediate-ca"):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    pki.chmod(0o700)
    private = pki / "root-ca/root-ca.key"
    private.write_text("installed backup private state\n", encoding="utf-8")
    private.chmod(0o600)
    destination = install.state / "backup-output"

    result = execute(
        process_runner,
        install,
        install.runtime / "platform-pki",
        "backup",
        "--pki-dir",
        pki,
        "--backup-dir",
        destination,
        "--allow-plain-backup",
    )

    assert result.status == 0, result.stderr
    assert "PKI backup contains secrets" in result.stderr
    archives = list(destination.glob("platform-pki-*.tar.gz"))
    receipts = list(destination.glob("platform-pki-*.tar.gz.receipt"))
    assert len(archives) == len(receipts) == 1
    assert archives[0].stat().st_mode & 0o777 == 0o600
    assert receipts[0].stat().st_mode & 0o777 == 0o600


def _prepare_export_state(
    process_runner: Callable[..., ProcessResult], install: Install, name: str
) -> Path:
    root = install.state / f"export-authority-{name}"
    pki = install.state / f"export-pki-{name}"
    for directory in (
        root,
        pki / "inventory",
        pki / "authorities/roots/g1/certs",
        pki / "authorities/intermediates/g1-i1/certs",
        pki / "services/api/certs",
        pki / "services/api/private",
        pki / "services/api/chain",
        pki / "export",
    ):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        directory.chmod(0o700)

    root_key = root / "root.key"
    root_certificate = root / "root.crt"
    intermediate_key = root / "intermediate.key"
    request = root / "intermediate.csr"
    intermediate_certificate = root / "intermediate.crt"
    commands = (
        (
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "365",
            "-subj",
            "/CN=InstalledExportRoot",
            "-keyout",
            root_key,
            "-out",
            root_certificate,
        ),
        (
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=InstalledExportIntermediate",
            "-keyout",
            intermediate_key,
            "-out",
            request,
        ),
        (
            "x509",
            "-req",
            "-in",
            request,
            "-CA",
            root_certificate,
            "-CAkey",
            root_key,
            "-CAcreateserial",
            "-days",
            "300",
            "-out",
            intermediate_certificate,
        ),
    )
    for arguments in commands:
        result = execute(
            process_runner, install, install.runtime / "openssl", *arguments
        )
        assert result.status == 0, result.stderr

    files = {
        pki / "inventory/services.yml": (
            b"services:\n  api:\n    common_name: api.example\n"
            b"    dns:\n      - api.example\n"
        ),
        pki / "state/active-issuer": b"root=g1\nintermediate=g1-i1\n",
        pki / "services/api/certs/tls.crt": b"api certificate\n",
        pki / "services/api/private/tls.key": b"api private key\n",
        pki / "services/api/chain/ca-chain.crt": b"api ca chain\n",
        pki / "services/api/chain/fullchain.crt": b"api full chain\n",
        pki / "services/api/issuer": b"root=g1\nintermediate=g1-i1\n",
    }
    for path, data in files.items():
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(0o600)
    shutil.copyfile(
        root_certificate, pki / "authorities/roots/g1/certs/root-ca.crt"
    )
    shutil.copyfile(
        intermediate_certificate,
        pki / "authorities/intermediates/g1-i1/certs/intermediate-ca.crt",
    )
    pki.chmod(0o700)
    return pki


def test_installed_export_ansible_operates_without_shell_libraries(
    process_runner: Callable[..., ProcessResult],
    install: Install,
) -> None:
    pki = _prepare_export_state(process_runner, install, "unified")
    destination = pki / "export/installed"

    result = execute(
        process_runner,
        install,
        install.runtime / "platform-pki",
        "export-ansible",
        "api",
        "--pki-dir",
        pki,
        "--export-dir",
        destination,
    )

    assert result.status == 0, result.stderr
    assert result.stdout == (
        "[OK] Exported service: api\n"
        f"[OK] Ansible export ready: {destination}\n"
    )
    assert result.stderr == (
        f"[WARN] Export contains service private keys: {destination}\n"
    )
    assert (destination / "services/api/tls.key").read_bytes() == b"api private key\n"
    assert (destination / "services/api/tls.key").stat().st_mode & 0o777 == 0o600


def test_installed_pki_command_prepares_legacy_control_state(
    process_runner: Callable[..., ProcessResult], install: Install
) -> None:
    pki = install.state / "legacy-pki"
    for directory in (pki / "inventory", pki / "root-ca", pki / "intermediate-ca"):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    pki.chmod(0o700)
    inventory = pki / "inventory/services.yml"
    inventory.write_text("services: {}\n", encoding="utf-8")
    inventory.chmod(0o600)

    result = execute(
        process_runner,
        install,
        install.runtime / "platform-pki",
        "list-expiry",
        "--pki-dir",
        pki,
    )

    assert result.status == 1
    assert result.stdout == ""
    assert result.stderr == LEGACY_MIGRATION_ERROR
    assert (pki / "locks").is_dir()
    assert (pki / "state/rollover").is_dir()
