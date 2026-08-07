from __future__ import annotations

import importlib.util
import os
import shutil
import sys
import zipfile
from collections.abc import Callable, Generator
from pathlib import Path

import pytest

from .harness import ProcessResult
from .pki.migration_contract import PKI_COMMAND_CONTRACTS, PKI_PARSER_ROUTES
from .test_platform_pki_parser import MINIMAL_ARGUMENTS
from src.platform_pki.parser import ROUTE_SPECS, render_usage


ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "bin/platform-pki"
PTY_CAPTURE = ROOT / "tests/cli/pty-capture.py"
VERSION = (ROOT / "VERSION").read_text(encoding="ascii").strip()
EXPECTED_MEMBERS = (
    "__main__.py",
    "platform_pki/__init__.py",
    "platform_pki/__main__.py",
    "platform_pki/_version.py",
    "platform_pki/cli.py",
    "platform_pki/compat.py",
    "platform_pki/errors.py",
    "platform_pki/faults.py",
    "platform_pki/filesystem.py",
    "platform_pki/inventory.py",
    "platform_pki/parser.py",
    "platform_pki/paths.py",
    "platform_pki/records.py",
    "platform_pki/subprocesses.py",
)


def _load_builder():
    path = ROOT / "scripts/build-platform-pki-zipapp.py"
    spec = importlib.util.spec_from_file_location("platform_pki_zipapp_builder", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BUILDER = _load_builder()


@pytest.fixture
def clean_environment(tmp_path: Path) -> Generator[dict[str, str], None, None]:
    paths = {name: tmp_path / name for name in ("home", "config", "data")}
    for path in paths.values():
        path.mkdir()
    environment = {
        **os.environ,
        "HOME": os.fspath(paths["home"]),
        "XDG_CONFIG_HOME": os.fspath(paths["config"]),
        "XDG_DATA_HOME": os.fspath(paths["data"]),
    }
    yield environment
    for path in paths.values():
        assert not any(path.iterdir()), f"platform-pki created state under {path}"


def _run(
    process_runner: Callable[..., ProcessResult],
    environment: dict[str, str],
    *arguments: str | Path,
    cwd: Path = ROOT,
) -> ProcessResult:
    return process_runner(arguments, cwd=cwd, env=environment)


def _assert_success(result: ProcessResult) -> None:
    assert result.status == 0, result.stderr
    assert result.stdout
    assert result.stderr == ""


def test_committed_zipapp_has_canonical_structure() -> None:
    assert ARTIFACT.is_file()
    assert not ARTIFACT.is_symlink()
    assert ARTIFACT.stat().st_mode & 0o777 == 0o755
    assert ARTIFACT.read_bytes().startswith(BUILDER.SHEBANG)
    with zipfile.ZipFile(ARTIFACT) as archive:
        members = archive.infolist()
        assert tuple(member.filename for member in members) == EXPECTED_MEMBERS
        assert all(member.date_time == BUILDER.ZIP_TIMESTAMP for member in members)
        assert all(member.compress_type == zipfile.ZIP_STORED for member in members)
        assert all(member.create_system == 3 for member in members)
        assert all((member.external_attr >> 16) & 0o777 == 0o644 for member in members)
        assert archive.read("platform_pki/_version.py") == f'VERSION = "{VERSION}"\n'.encode()
        assert archive.testzip() is None


def test_build_is_byte_deterministic_and_ignores_mtimes_umask_and_caches(
    tmp_path: Path,
) -> None:
    source = tmp_path / "src/platform_pki"
    shutil.copytree(ROOT / "src/platform_pki", source)
    cache = source / "__pycache__"
    cache.mkdir(exist_ok=True)
    (cache / "ignored.pyc").write_bytes(b"not bytecode")
    first = tmp_path / "first/platform-pki"
    second = tmp_path / "second/platform-pki"

    previous_umask = os.umask(0o077)
    try:
        BUILDER.build_archive(source, ROOT / "VERSION", first)
        for path in source.rglob("*.py"):
            os.utime(path, (1_900_000_000, 1_900_000_000))
        os.umask(0o022)
        BUILDER.build_archive(source, ROOT / "VERSION", second)
    finally:
        os.umask(previous_umask)

    assert first.read_bytes() == second.read_bytes() == ARTIFACT.read_bytes()
    assert first.stat().st_mode & 0o777 == second.stat().st_mode & 0o777 == 0o755


def test_failed_build_preserves_existing_output_and_removes_temporary_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "src/platform_pki"
    shutil.copytree(ROOT / "src/platform_pki", source)
    output = tmp_path / "platform-pki"
    output.write_bytes(b"existing archive")
    unexpected = source / "data.txt"
    unexpected.write_text("unexpected\n", encoding="ascii")
    with pytest.raises(ValueError, match="unexpected zipapp source file"):
        BUILDER.build_archive(source, ROOT / "VERSION", output)
    assert output.read_bytes() == b"existing archive"
    unexpected.unlink()
    (source / "linked.py").symlink_to(source / "cli.py")
    with pytest.raises(ValueError, match="must not contain symlinks"):
        BUILDER.build_archive(source, ROOT / "VERSION", output)
    assert output.read_bytes() == b"existing archive"
    (source / "linked.py").unlink()

    def fail_write(*_arguments, **_keywords):
        raise OSError("injected archive write failure")

    monkeypatch.setattr(BUILDER.zipfile.ZipFile, "writestr", fail_write)
    with pytest.raises(OSError, match="injected archive write failure"):
        BUILDER.build_archive(source, ROOT / "VERSION", output)
    assert output.read_bytes() == b"existing archive"
    assert not tuple(tmp_path.glob(f".{output.name}.*"))


@pytest.mark.parametrize("flag", ("--help", "-h"))
def test_root_help_is_plain_and_state_free(
    process_runner: Callable[..., ProcessResult],
    clean_environment: dict[str, str],
    flag: str,
) -> None:
    result = _run(process_runner, clean_environment, ARTIFACT, flag)
    _assert_success(result)
    assert "Usage: platform-pki COMMAND [OPTIONS]" in result.stdout
    assert "\033" not in result.stdout


@pytest.mark.parametrize("flag", ("--version", "-v"))
def test_root_version_is_embedded_and_state_free(
    process_runner: Callable[..., ProcessResult],
    clean_environment: dict[str, str],
    flag: str,
) -> None:
    result = _run(process_runner, clean_environment, ARTIFACT, flag)
    _assert_success(result)
    assert result.stdout == f"platform-pki {VERSION}\n"


def test_leading_root_action_precedes_later_invalid_arguments(
    process_runner: Callable[..., ProcessResult],
    clean_environment: dict[str, str],
) -> None:
    for action in ("--help", "--version"):
        result = _run(
            process_runner,
            clean_environment,
            ARTIFACT,
            action,
            "--invalid-after-action",
        )
        _assert_success(result)


def test_parser_and_unavailable_handler_fail_without_state(
    process_runner: Callable[..., ProcessResult],
    clean_environment: dict[str, str],
) -> None:
    for arguments in (("--invalid",), ("init",)):
        result = _run(process_runner, clean_environment, ARTIFACT, *arguments)
        assert result.status == 1
        assert result.stdout == ""
        assert result.stderr.startswith("[ERROR] ")
        assert "\033" not in result.stderr


@pytest.mark.parametrize(
    "route",
    PKI_PARSER_ROUTES,
    ids=("-".join(route.unified_route) for route in PKI_PARSER_ROUTES),
)
def test_every_frozen_unified_route_has_state_free_help(
    process_runner: Callable[..., ProcessResult],
    clean_environment: dict[str, str],
    route,
) -> None:
    result = _run(
        process_runner,
        clean_environment,
        ARTIFACT,
        *route.unified_route,
        "--help",
    )
    _assert_success(result)
    assert "\033" not in result.stdout
    for option in route.long_flags:
        assert option in result.stdout


@pytest.mark.parametrize(
    "route",
    PKI_PARSER_ROUTES,
    ids=("-".join(route.unified_route) for route in PKI_PARSER_ROUTES),
)
def test_every_frozen_unified_route_parses_then_fails_closed_without_state(
    process_runner: Callable[..., ProcessResult],
    clean_environment: dict[str, str],
    route,
) -> None:
    result = _run(
        process_runner,
        clean_environment,
        ARTIFACT,
        *route.unified_route,
        *MINIMAL_ARGUMENTS[route.unified_route],
    )
    assert result.status == 1
    assert result.stdout == ""
    assert result.stderr == (
        "[ERROR] Command is not available in the Python foundation: "
        f"{' '.join(route.unified_route)}\n"
    )


@pytest.mark.parametrize(
    "route",
    PKI_PARSER_ROUTES,
    ids=("-".join(route.unified_route) for route in PKI_PARSER_ROUTES),
)
def test_every_frozen_unified_route_rejects_abbreviations_without_state(
    process_runner: Callable[..., ProcessResult],
    clean_environment: dict[str, str],
    route,
) -> None:
    result = _run(
        process_runner,
        clean_environment,
        ARTIFACT,
        *route.unified_route,
        *MINIMAL_ARGUMENTS[route.unified_route],
        "--namesp=/tmp/unsupported",
    )
    assert result.status == 1
    assert result.stdout == ""
    assert result.stderr == "invalid option: --namesp\n"


@pytest.mark.parametrize(
    "route",
    PKI_PARSER_ROUTES,
    ids=("-".join(route.unified_route) for route in PKI_PARSER_ROUTES),
)
@pytest.mark.parametrize(
    "probe",
    (
        "--namesp=/tmp/unsupported",
        "--help=x",
        "-hfoo",
        "--bad.name=x",
        "-h/",
        "-h\N{LATIN SMALL LETTER E WITH ACUTE}",
    ),
)
def test_every_route_matches_bashly_unknown_token_normalization(
    process_runner: Callable[..., ProcessResult],
    clean_environment: dict[str, str],
    route,
    probe: str,
) -> None:
    nested = route.unified_route[1:]
    minimal = MINIMAL_ARGUMENTS[route.unified_route]
    bash = _run(
        process_runner,
        clean_environment,
        ROOT / "bin" / route.compatibility_executable,
        *nested,
        *minimal,
        probe,
    )
    python = _run(
        process_runner,
        clean_environment,
        ARTIFACT,
        *route.unified_route,
        *minimal,
        probe,
    )
    if bash.status == python.status == 0:
        assert bash.stdout and python.stdout
        assert "Usage:" in bash.stdout and "Usage:" in python.stdout
        assert bash.stderr == python.stderr == ""
    else:
        assert (python.status, python.stdout, python.stderr) == (
            bash.status,
            bash.stdout,
            bash.stderr,
        )


@pytest.mark.parametrize(
    "contract",
    PKI_COMMAND_CONTRACTS,
    ids=(contract.compatibility_name for contract in PKI_COMMAND_CONTRACTS),
)
def test_copied_compatibility_name_dispatches_outside_checkout(
    process_runner: Callable[..., ProcessResult],
    clean_environment: dict[str, str],
    tmp_path: Path,
    contract,
) -> None:
    copied = tmp_path / "installed" / contract.compatibility_name
    copied.parent.mkdir()
    shutil.copy2(ARTIFACT, copied)
    version = _run(process_runner, clean_environment, copied, "--version", cwd=tmp_path)
    _assert_success(version)
    assert version.stdout == f"{contract.compatibility_name} {VERSION}\n"

    help_result = _run(process_runner, clean_environment, copied, "--help", cwd=tmp_path)
    _assert_success(help_result)
    if contract.nested_commands:
        expected_usage = f"Usage: {contract.compatibility_name} COMMAND [OPTIONS]\n"
    else:
        expected_usage = render_usage(
            contract.compatibility_name,
            ROUTE_SPECS[(contract.unified_route,)],
            compatibility=True,
        )
    assert help_result.stdout.startswith(expected_usage)

    invalid = _run(process_runner, clean_environment, copied, "--invalid", cwd=tmp_path)
    assert invalid.status == 1
    assert invalid.stdout == ""
    if contract.nested_commands:
        assert invalid.stderr.startswith("[ERROR] Unknown ")
    else:
        assert invalid.stderr == "invalid option: --invalid\n"

    route = (
        (contract.unified_route, contract.nested_commands[0])
        if contract.nested_commands
        else (contract.unified_route,)
    )
    operational_arguments = (
        (*contract.nested_commands[:1], *MINIMAL_ARGUMENTS[route])
    )
    unavailable = _run(
        process_runner,
        clean_environment,
        copied,
        *operational_arguments,
        cwd=tmp_path,
    )
    assert unavailable.status == 1
    assert unavailable.stdout == ""
    assert "not available in the Python foundation" in unavailable.stderr

    for nested in contract.nested_commands:
        nested_help = _run(
            process_runner,
            clean_environment,
            copied,
            nested,
            "--help",
            cwd=tmp_path,
        )
        _assert_success(nested_help)
        assert nested_help.stdout.startswith(
            render_usage(
                contract.compatibility_name,
                ROUTE_SPECS[(contract.unified_route, nested)],
                compatibility=True,
            )
        )


def test_unknown_copied_invocation_name_fails_closed_before_actions(
    process_runner: Callable[..., ProcessResult],
    clean_environment: dict[str, str],
    tmp_path: Path,
) -> None:
    copied = tmp_path / "installed/platform-pki-unknown"
    copied.parent.mkdir()
    shutil.copy2(ARTIFACT, copied)
    for action in ("--help", "--version"):
        result = _run(process_runner, clean_environment, copied, action, cwd=tmp_path)
        assert result.status == 1
        assert result.stdout == ""
        assert result.stderr == (
            "[ERROR] Unsupported invocation name: platform-pki-unknown\n"
        )


def test_python_version_guard_precedes_cli_import(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from src.platform_pki import __main__ as package_main

    monkeypatch.setattr(package_main.sys, "version_info", (3, 13))
    monkeypatch.setitem(sys.modules, "src.platform_pki.cli", None)
    assert package_main.main() == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "platform-pki requires Python 3.14 or newer\n"
    assert sys.modules["src.platform_pki.cli"] is None


def test_copied_execution_ignores_import_and_shell_overrides(
    process_runner: Callable[..., ProcessResult],
    clean_environment: dict[str, str],
    tmp_path: Path,
) -> None:
    copied = tmp_path / "installed/platform-pki"
    copied.parent.mkdir()
    shutil.copy2(ARTIFACT, copied)
    poison = tmp_path / "poison/platform_pki"
    poison.mkdir(parents=True)
    (poison / "__init__.py").write_text(
        'raise RuntimeError("external platform_pki imported")\n',
        encoding="ascii",
    )
    environment = {
        **clean_environment,
        "PYTHONPATH": os.fspath(poison.parent),
        "PYTHONHOME": os.fspath(poison.parent),
        "PYTHONUSERBASE": os.fspath(poison.parent),
        "BASH_ENV": os.fspath(poison / "bash-env"),
        "ENV": os.fspath(poison / "sh-env"),
        "PLATFORM_TOOLS_LIB_DIR": os.fspath(poison),
        "PLATFORM_TOOLS_SHARE_DIR": os.fspath(poison),
        "PLATFORM_TOOLS_TEMPLATE_DIR": os.fspath(poison),
    }
    result = _run(process_runner, environment, copied, "--version", cwd=poison.parent)
    _assert_success(result)
    assert result.stdout == f"platform-pki {VERSION}\n"


def test_tty_help_color_and_no_color(
    process_runner: Callable[..., ProcessResult],
    clean_environment: dict[str, str],
) -> None:
    colored = _run(
        process_runner,
        clean_environment,
        "python3",
        PTY_CAPTURE,
        ARTIFACT,
        "--help",
    )
    _assert_success(colored)
    assert "\033" in colored.stdout

    plain = _run(
        process_runner,
        {**clean_environment, "NO_COLOR": "1"},
        "python3",
        PTY_CAPTURE,
        ARTIFACT,
        "--help",
    )
    _assert_success(plain)
    assert "\033" not in plain.stdout
