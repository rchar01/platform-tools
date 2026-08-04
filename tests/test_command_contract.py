from __future__ import annotations

import os
from collections.abc import Callable, Generator
from pathlib import Path

import pytest

from .harness import ProcessResult, run_process


ROOT = Path(__file__).resolve().parents[1]
VERSION = (ROOT / "VERSION").read_text().strip()
PTY_CAPTURE = ROOT / "tests/cli/pty-capture.py"


def make_variables(*names: str) -> dict[str, tuple[str, ...]]:
    rules = []
    for name in names:
        rules.extend(
            (
                f".PHONY: pytest-print-{name}",
                f"pytest-print-{name}:",
                f"\t@printf '%s\\n' '$({name})'",
            )
        )
    result = run_process(
        ("make", "-s", "--no-print-directory", "-f", "Makefile", "-f", "-", *(f"pytest-print-{name}" for name in names)),
        cwd=ROOT,
        input="\n".join(rules) + "\n",
        timeout=30,
    )
    if result.status != 0 or result.stderr:
        raise RuntimeError(
            f"failed to query Make inventories: status={result.status}, stderr={result.stderr!r}"
        )
    values = result.stdout.splitlines()
    assert len(values) == len(names), result.stdout
    variables = {name: tuple(value.split()) for name, value in zip(names, values, strict=True)}
    for name, entries in variables.items():
        if not entries:
            raise RuntimeError(f"Make variable {name} must not be empty")
        if len(entries) != len(set(entries)):
            raise RuntimeError(f"Make variable {name} contains duplicates")
    return variables


MAKE = make_variables("SHELL_TOOLS", "BASHLY_TOOLS", "PYTHON_TOOLS")
SHELL_TOOLS = MAKE["SHELL_TOOLS"]
BASHLY_TOOLS = MAKE["BASHLY_TOOLS"]
PYTHON_TOOLS = MAKE["PYTHON_TOOLS"]
TOOLS = SHELL_TOOLS + PYTHON_TOOLS
if set(SHELL_TOOLS) & set(PYTHON_TOOLS):
    raise RuntimeError("SHELL_TOOLS and PYTHON_TOOLS must not overlap")


@pytest.fixture
def clean_env(tmp_path: Path) -> Generator[dict[str, str], None, None]:
    paths = {name: tmp_path / name for name in ("home", "config", "data")}
    for path in paths.values():
        path.mkdir()
    env = {
        **os.environ,
        "HOME": os.fspath(paths["home"]),
        "XDG_CONFIG_HOME": os.fspath(paths["config"]),
        "XDG_DATA_HOME": os.fspath(paths["data"]),
    }
    yield env
    for path in paths.values():
        assert not any(path.iterdir()), f"contract query created state under {path}"


def run(
    process_runner: Callable[..., ProcessResult],
    clean_env: dict[str, str],
    *args: str | Path,
) -> ProcessResult:
    return process_runner(args, cwd=ROOT, env=clean_env)


def assert_success_stdout(result: ProcessResult) -> None:
    assert result.status == 0, result.stderr
    assert result.stdout
    assert result.stderr == ""


def assert_parser_error(result: ProcessResult) -> None:
    assert result.status == 1
    assert result.stdout == ""
    assert result.stderr


@pytest.mark.parametrize("tool", SHELL_TOOLS, ids=SHELL_TOOLS)
def test_shell_tool_is_bashly_generated(tool: str) -> None:
    assert tool in BASHLY_TOOLS
    assert (ROOT / "bashly" / tool / "settings.yml").is_file()
    assert (ROOT / "bashly" / tool / "src/bashly.yml").is_file()
    command = ROOT / "bin" / tool
    assert command.is_file()
    assert os.access(command, os.X_OK)


@pytest.mark.parametrize("tool", BASHLY_TOOLS, ids=BASHLY_TOOLS)
def test_bashly_tool_is_in_shell_inventory(tool: str) -> None:
    assert tool in SHELL_TOOLS


@pytest.mark.parametrize("tool", TOOLS, ids=TOOLS)
@pytest.mark.parametrize("flag", ("--help", "-h"), ids=("long", "short"))
def test_root_help(
    process_runner: Callable[..., ProcessResult], clean_env: dict[str, str], tool: str, flag: str
) -> None:
    result = run(process_runner, clean_env, ROOT / "bin" / tool, flag)
    assert_success_stdout(result)
    assert "\x1b" not in result.stdout


@pytest.mark.parametrize("tool", TOOLS, ids=TOOLS)
@pytest.mark.parametrize("flag", ("--version", "-v"), ids=("long", "short"))
def test_root_version(
    process_runner: Callable[..., ProcessResult], clean_env: dict[str, str], tool: str, flag: str
) -> None:
    result = run(process_runner, clean_env, ROOT / "bin" / tool, flag)
    assert_success_stdout(result)
    assert result.stdout == f"{tool} {VERSION}\n"


@pytest.mark.parametrize("tool", TOOLS, ids=TOOLS)
@pytest.mark.parametrize("action", ("--help", "--version"), ids=("help", "version"))
def test_leading_root_action_has_precedence(
    process_runner: Callable[..., ProcessResult], clean_env: dict[str, str], tool: str, action: str
) -> None:
    result = run(process_runner, clean_env, ROOT / "bin" / tool, action, "--contract-invalid-option")
    assert_success_stdout(result)
    if action == "--version":
        assert result.stdout == f"{tool} {VERSION}\n"


@pytest.mark.parametrize("tool", TOOLS, ids=TOOLS)
@pytest.mark.parametrize(
    "suffix",
    ((), ("--help",), ("--version",)),
    ids=("invalid", "before-help", "before-version"),
)
def test_root_parser_error(
    process_runner: Callable[..., ProcessResult],
    clean_env: dict[str, str],
    tool: str,
    suffix: tuple[str, ...],
) -> None:
    assert_parser_error(
        run(process_runner, clean_env, ROOT / "bin" / tool, "--contract-invalid-option", *suffix)
    )


@pytest.mark.parametrize("tool", SHELL_TOOLS, ids=SHELL_TOOLS)
def test_tty_help_is_colored(
    process_runner: Callable[..., ProcessResult], clean_env: dict[str, str], tool: str
) -> None:
    result = run(
        process_runner,
        clean_env,
        "python3",
        PTY_CAPTURE,
        ROOT / "bin" / tool,
        "--help",
    )
    assert_success_stdout(result)
    assert "\x1b" in result.stdout


@pytest.mark.parametrize("tool", SHELL_TOOLS, ids=SHELL_TOOLS)
def test_no_color_suppresses_tty_help_color(
    process_runner: Callable[..., ProcessResult], clean_env: dict[str, str], tool: str
) -> None:
    env = {**clean_env, "NO_COLOR": "1"}
    result = run(
        process_runner,
        env,
        "python3",
        PTY_CAPTURE,
        ROOT / "bin" / tool,
        "--help",
    )
    assert_success_stdout(result)
    assert "\x1b" not in result.stdout


SNAPSHOT_SUBCOMMANDS = ("create", "list", "rollback", "delete")


@pytest.mark.parametrize("subcommand", SNAPSHOT_SUBCOMMANDS)
@pytest.mark.parametrize("flag", ("--help", "-h"), ids=("long", "short"))
def test_snapshot_subcommand_help(
    process_runner: Callable[..., ProcessResult], clean_env: dict[str, str], subcommand: str, flag: str
) -> None:
    result = run(
        process_runner, clean_env, ROOT / "bin/platform-proxmox-vm-snapshot", subcommand, flag
    )
    assert_success_stdout(result)


@pytest.mark.parametrize("subcommand", SNAPSHOT_SUBCOMMANDS)
@pytest.mark.parametrize("action", ("--help", "--version"), ids=("help", "version"))
def test_snapshot_subcommand_invalid_option_before_action(
    process_runner: Callable[..., ProcessResult], clean_env: dict[str, str], subcommand: str, action: str
) -> None:
    assert_parser_error(
        run(
            process_runner,
            clean_env,
            ROOT / "bin/platform-proxmox-vm-snapshot",
            subcommand,
            "--contract-invalid-option",
            action,
        )
    )


def test_snapshot_create_invalid_option(
    process_runner: Callable[..., ProcessResult], clean_env: dict[str, str]
) -> None:
    assert_parser_error(
        run(
            process_runner,
            clean_env,
            ROOT / "bin/platform-proxmox-vm-snapshot",
            "create",
            "--contract-invalid-option",
        )
    )


BASTION_SUBCOMMANDS = ("validate", "render-host", "render-csr-configmap")
VALID_POLICY = ROOT / "tests/bastion-policy/fixtures/access-policy.valid.yaml"


@pytest.mark.parametrize("subcommand", BASTION_SUBCOMMANDS)
@pytest.mark.parametrize("flag", ("--help", "-h"), ids=("long", "short"))
def test_bastion_subcommand_help(
    process_runner: Callable[..., ProcessResult], clean_env: dict[str, str], subcommand: str, flag: str
) -> None:
    assert_success_stdout(
        run(process_runner, clean_env, ROOT / "bin/platform-bastion-policy", subcommand, flag)
    )


@pytest.mark.parametrize("subcommand", BASTION_SUBCOMMANDS)
@pytest.mark.parametrize("action", ("--help", "--version"), ids=("help", "version"))
def test_bastion_invalid_option_before_action(
    process_runner: Callable[..., ProcessResult], clean_env: dict[str, str], subcommand: str, action: str
) -> None:
    assert_parser_error(
        run(
            process_runner,
            clean_env,
            ROOT / "bin/platform-bastion-policy",
            subcommand,
            "--contract-invalid-option",
            action,
        )
    )


@pytest.mark.parametrize("subcommand", BASTION_SUBCOMMANDS)
def test_bastion_rejects_abbreviated_option(
    process_runner: Callable[..., ProcessResult], clean_env: dict[str, str], subcommand: str
) -> None:
    assert_parser_error(
        run(
            process_runner,
            clean_env,
            ROOT / "bin/platform-bastion-policy",
            subcommand,
            "--inp",
            VALID_POLICY,
        )
    )


@pytest.mark.parametrize("subcommand", BASTION_SUBCOMMANDS)
@pytest.mark.parametrize(
    ("prefix", "action", "expected"),
    (
        (("--inp", "value"), "--help", "error"),
        (("--help",), "--inp", "success"),
        (("--inp", "value"), "--version", "error"),
        (("--version",), "--inp", "error"),
    ),
    ids=("abbreviation-before-help", "abbreviation-after-help", "abbreviation-before-version", "abbreviation-after-version"),
)
def test_bastion_abbreviation_action_order(
    process_runner: Callable[..., ProcessResult],
    clean_env: dict[str, str],
    subcommand: str,
    prefix: tuple[str, ...],
    action: str,
    expected: str,
) -> None:
    tail = (action, "value") if action == "--inp" else (action,)
    result = run(
        process_runner, clean_env, ROOT / "bin/platform-bastion-policy", subcommand, *prefix, *tail
    )
    (assert_success_stdout if expected == "success" else assert_parser_error)(result)


@pytest.mark.parametrize("subcommand", BASTION_SUBCOMMANDS)
@pytest.mark.parametrize("action", ("--help", "--version"), ids=("help", "version"))
def test_bastion_valid_option_before_action(
    process_runner: Callable[..., ProcessResult],
    clean_env: dict[str, str],
    subcommand: str,
    action: str,
) -> None:
    result = run(
        process_runner,
        clean_env,
        ROOT / "bin/platform-bastion-policy",
        subcommand,
        "--input",
        VALID_POLICY,
        action,
    )
    (assert_success_stdout if action == "--help" else assert_parser_error)(result)


@pytest.mark.parametrize("subcommand", BASTION_SUBCOMMANDS)
@pytest.mark.parametrize("action", ("--help", "--version"), ids=("help", "version"))
def test_bastion_invalid_option_after_action(
    process_runner: Callable[..., ProcessResult],
    clean_env: dict[str, str],
    subcommand: str,
    action: str,
) -> None:
    result = run(
        process_runner,
        clean_env,
        ROOT / "bin/platform-bastion-policy",
        subcommand,
        action,
        "--contract-invalid-option",
    )
    (assert_success_stdout if action == "--help" else assert_parser_error)(result)


def test_bastion_validate_invalid_option(
    process_runner: Callable[..., ProcessResult], clean_env: dict[str, str]
) -> None:
    assert_parser_error(
        run(
            process_runner,
            clean_env,
            ROOT / "bin/platform-bastion-policy",
            "validate",
            "--contract-invalid-option",
        )
    )


@pytest.mark.parametrize("abbreviation", ("--hel", "--ver"))
def test_bastion_rejects_abbreviated_root_option(
    process_runner: Callable[..., ProcessResult], clean_env: dict[str, str], abbreviation: str
) -> None:
    assert_parser_error(
        run(process_runner, clean_env, ROOT / "bin/platform-bastion-policy", abbreviation)
    )


@pytest.mark.parametrize(
    "args", (("--help", "--ver"), ("--version", "--hel")), ids=("after-help", "after-version")
)
def test_bastion_root_action_precedes_abbreviation(
    process_runner: Callable[..., ProcessResult], clean_env: dict[str, str], args: tuple[str, str]
) -> None:
    assert_success_stdout(run(process_runner, clean_env, ROOT / "bin/platform-bastion-policy", *args))


@pytest.mark.parametrize("tool", TOOLS, ids=TOOLS)
def test_contract_queries_create_no_state(
    process_runner: Callable[..., ProcessResult], clean_env: dict[str, str], tool: str
) -> None:
    command = ROOT / "bin" / tool
    for args in (("--help",), ("--version",), ("--contract-invalid-option",)):
        run(process_runner, clean_env, command, *args)
    for variable in ("HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME"):
        assert not any(Path(clean_env[variable]).iterdir())
