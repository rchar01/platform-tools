from __future__ import annotations

import os
import shutil
import tempfile
from collections.abc import Callable, Generator
from dataclasses import dataclass
from pathlib import Path

import pytest

from .harness import ProcessResult, run_process


ROOT = Path(__file__).resolve().parents[1]
VERSION = (ROOT / "VERSION").read_text().strip()


def make_tools() -> tuple[str, ...]:
    rule = ".PHONY: pytest-print-tools\npytest-print-tools:\n\t@printf '%s\\n' '$(TOOLS)'\n"
    result = run_process(
        ("make", "-s", "--no-print-directory", "-f", "Makefile", "-f", "-", "pytest-print-tools"),
        cwd=ROOT,
        input=rule,
        timeout=30,
    )
    if result.status != 0 or result.stderr:
        raise RuntimeError(
            f"failed to query Make inventory: status={result.status}, stderr={result.stderr!r}"
        )
    tools = tuple(result.stdout.split())
    if not tools:
        raise RuntimeError("Make variable TOOLS must not be empty")
    if len(tools) != len(set(tools)):
        raise RuntimeError("Make variable TOOLS contains duplicates")
    return tools


TOOLS = make_tools()
DEPENDENCIES = ("bash", "python3", "dirname", "mkdir", "chmod", "id", "stat", "find", "mktemp", "cp", "mv", "rm", "pwd", "flock", "openssl")
LEGACY_MIGRATION_ERROR = (
    "[ERROR] Legacy PKI state requires migration; create a fresh backup and "
    "follow platform-pki-ca-rollover status/migrate\n"
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
        (value.staged_bin, staged_base / "install/share/platform-tools"),
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
    adjacent_library = install.install_bin.parent / "lib/platform-pki-common.sh"
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
    process_runner: Callable[..., ProcessResult], install: Install
) -> None:
    namespace = install.state / "pki-namespace"
    result = execute(
        process_runner,
        install,
        install.runtime / "platform-pki-init",
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
        install.runtime / "platform-pki-list-expiry",
        "--pki-dir",
        pki,
    )

    assert result.status == 1
    assert result.stdout == ""
    assert result.stderr == LEGACY_MIGRATION_ERROR
    assert (pki / "locks").is_dir()
    assert (pki / "state/rollover").is_dir()
