from collections.abc import Callable, Mapping
from pathlib import Path

import pytest

from ..harness import ProcessResult


pytestmark = pytest.mark.pki

PREPARE_CLI = [
    "prepare",
    "--namespace",
    "/tmp/unused",
    "--pki-dir",
    "/tmp/unused/pki",
    "--type",
    "intermediate",
    "--backup-receipt",
    "/tmp/unused.receipt",
    "--intermediate-name",
    "Test",
    "--org",
    "Test",
    "--country",
    "US",
    "--root-pass-file",
    "/tmp/unused-root-pass",
    "--intermediate-pass-file",
    "/tmp/unused-intermediate-pass",
    "--issuer-safety-days",
    "1",
]

RECOVER_CLI = [
    "recover",
    "--namespace",
    "/tmp/unused",
    "--pki-dir",
    "/tmp/unused/pki",
    "--transaction",
    "prepare-root-20260730-000000-1",
    "--action",
    "rollback",
    "--yes",
]

PREPARE_REPEATED_OPTIONS = [
    ("--namespace", "/tmp/other"),
    ("--pki-dir", "/tmp/other"),
    ("--type", "root"),
    ("--backup-receipt", "/tmp/other"),
    ("--intermediate-name", "Other"),
    ("--org", "Other"),
    ("--country", "PL"),
    ("--root-pass-file", "/tmp/other"),
    ("--intermediate-pass-file", "/tmp/other"),
    ("--issuer-safety-days", "2"),
]

PREPARE_OPTIONAL_REPEATED_OPTIONS = [
    ("--root-name", "Root"),
    ("--root-days", "2"),
    ("--intermediate-days", "2"),
    ("--private-repo", "/tmp/private"),
]

RECOVER_REPEATED_OPTIONS = [
    ("--namespace", "/tmp/other"),
    ("--pki-dir", "/tmp/other"),
    ("--transaction", "prepare-root-20260730-000000-2"),
    ("--action", "resume"),
]

PREPARE_REQUIRED_OPTIONS = [
    "--namespace",
    "--pki-dir",
    "--type",
    "--backup-receipt",
    "--intermediate-name",
    "--org",
    "--country",
    "--root-pass-file",
    "--intermediate-pass-file",
    "--issuer-safety-days",
]

PREPARE_OPTIONAL_OPTIONS = [
    "--root-name",
    "--root-days",
    "--intermediate-days",
    "--private-repo",
]

RECOVER_REQUIRED_OPTIONS = [
    "--namespace",
    "--pki-dir",
    "--transaction",
    "--action",
]

RECOVER_FORBIDDEN_OPTIONS = [
    "--backup-receipt",
    "--type",
    "--root-name",
    "--intermediate-name",
    "--org",
    "--country",
    "--root-days",
    "--intermediate-days",
    "--root-pass-file",
    "--intermediate-pass-file",
    "--issuer-safety-days",
    "--private-repo",
]

PREPARE_FORBIDDEN_OPTIONS = ["--transaction", "--action", "--yes"]


def option_id(value: object) -> str:
    if isinstance(value, tuple):
        value = value[0]
    return str(value).removeprefix("--")


def without_option(arguments: list[str], rejected: str) -> list[str]:
    index = arguments.index(rejected)
    return arguments[:index] + arguments[index + 2 :]


def isolate_arguments(arguments: list[str], tmp_path: Path) -> list[str]:
    return [
        str(tmp_path / argument.removeprefix("/tmp/"))
        if argument.startswith("/tmp/")
        else argument
        for argument in arguments
    ]


def run_parser_command(
    tmp_path: Path,
    rollover_tool: Path,
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
    arguments: list[str],
) -> ProcessResult:
    return process_runner(
        [rollover_tool, *isolate_arguments(arguments, tmp_path)],
        env=isolated_environment,
        timeout=10,
    )


def assert_parser_paths_untouched(tmp_path: Path) -> None:
    assert not (tmp_path / "config/platform-infrastructure").exists()
    for path in (
        "unused",
        "unused.receipt",
        "unused-root-pass",
        "unused-intermediate-pass",
        "other",
        "private",
    ):
        assert not (tmp_path / path).exists()


def assert_parser_failure(
    result: ProcessResult, tmp_path: Path, *expected_stderr_fragments: str
) -> None:
    assert result.status == 1
    assert result.stdout == ""
    for fragment in expected_stderr_fragments:
        assert fragment in result.stderr
    assert_parser_paths_untouched(tmp_path)


def empty_option_diagnostic(option: str) -> tuple[str, ...]:
    explicit_diagnostics = {
        "--type": "[ERROR] Candidate type must not be empty\n",
        "--issuer-safety-days": (
            "[ERROR] Option must not be empty: --issuer-safety-days\n"
        ),
        "--action": "[ERROR] Recovery action must not be empty\n",
    }
    if option in explicit_diagnostics:
        return (explicit_diagnostics[option],)
    return (f"validation error in {option} ", "must not be empty\n")


def test_help_describes_available_rollover_lifecycle(
    tmp_path: Path,
    rollover_tool: Path,
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> None:
    result = run_parser_command(
        tmp_path, rollover_tool, isolated_environment, process_runner, ["--help"]
    )

    assert result.status == 0
    assert result.stderr == ""
    assert "candidate preparation, recovery, and status" in result.stdout
    assert (
        "activate, acknowledge, rollback, retire, and complete remain unavailable"
        in result.stdout
    )


def test_status_rejects_repeated_format(
    tmp_path: Path,
    rollover_tool: Path,
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> None:
    result = run_parser_command(
        tmp_path,
        rollover_tool,
        isolated_environment,
        process_runner,
        ["status", "--format", "text", "--format", "json"],
    )

    assert result.status == 1
    assert result.stdout == ""
    assert result.stderr == "[ERROR] Option must not be repeated: --format\n"
    assert_parser_paths_untouched(tmp_path)


@pytest.mark.parametrize(
    ("option", "value"), PREPARE_REPEATED_OPTIONS, ids=option_id
)
def test_prepare_rejects_repeated_required_option(
    tmp_path: Path,
    rollover_tool: Path,
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
    option: str,
    value: str,
) -> None:
    result = run_parser_command(
        tmp_path,
        rollover_tool,
        isolated_environment,
        process_runner,
        [*PREPARE_CLI, option, value],
    )

    assert result.status == 1
    assert result.stdout == ""
    assert result.stderr == f"[ERROR] Option must not be repeated: {option}\n"
    assert_parser_paths_untouched(tmp_path)


@pytest.mark.parametrize(
    ("option", "value"), PREPARE_OPTIONAL_REPEATED_OPTIONS, ids=option_id
)
def test_prepare_rejects_repeated_optional_option(
    tmp_path: Path,
    rollover_tool: Path,
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
    option: str,
    value: str,
) -> None:
    result = run_parser_command(
        tmp_path,
        rollover_tool,
        isolated_environment,
        process_runner,
        [*PREPARE_CLI, option, value, option, value],
    )

    assert result.status == 1
    assert result.stdout == ""
    assert result.stderr == f"[ERROR] Option must not be repeated: {option}\n"
    assert_parser_paths_untouched(tmp_path)


@pytest.mark.parametrize(
    ("option", "value"), RECOVER_REPEATED_OPTIONS, ids=option_id
)
def test_recover_rejects_repeated_option(
    tmp_path: Path,
    rollover_tool: Path,
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
    option: str,
    value: str,
) -> None:
    result = run_parser_command(
        tmp_path,
        rollover_tool,
        isolated_environment,
        process_runner,
        [*RECOVER_CLI, option, value],
    )

    assert result.status == 1
    assert result.stdout == ""
    assert result.stderr == f"[ERROR] Option must not be repeated: {option}\n"
    assert_parser_paths_untouched(tmp_path)


def test_recover_rejects_repeated_yes(
    tmp_path: Path,
    rollover_tool: Path,
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> None:
    result = run_parser_command(
        tmp_path,
        rollover_tool,
        isolated_environment,
        process_runner,
        [*RECOVER_CLI, "--yes"],
    )

    assert result.status == 1
    assert result.stdout == ""
    assert result.stderr == "[ERROR] Option must not be repeated: --yes\n"
    assert_parser_paths_untouched(tmp_path)


@pytest.mark.parametrize("option", PREPARE_REQUIRED_OPTIONS, ids=option_id)
def test_prepare_rejects_empty_required_option(
    tmp_path: Path,
    rollover_tool: Path,
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
    option: str,
) -> None:
    arguments = [*without_option(PREPARE_CLI, option), option, ""]
    result = run_parser_command(
        tmp_path, rollover_tool, isolated_environment, process_runner, arguments
    )

    assert_parser_failure(result, tmp_path, *empty_option_diagnostic(option))


@pytest.mark.parametrize("option", PREPARE_OPTIONAL_OPTIONS, ids=option_id)
def test_prepare_rejects_empty_optional_option(
    tmp_path: Path,
    rollover_tool: Path,
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
    option: str,
) -> None:
    result = run_parser_command(
        tmp_path,
        rollover_tool,
        isolated_environment,
        process_runner,
        [*PREPARE_CLI, option, ""],
    )

    assert_parser_failure(result, tmp_path, *empty_option_diagnostic(option))


def test_prepare_rejects_equals_form_empty_defaulted_option(
    tmp_path: Path,
    rollover_tool: Path,
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> None:
    arguments = [
        *without_option(PREPARE_CLI, "--issuer-safety-days"),
        "--issuer-safety-days=",
    ]
    result = run_parser_command(
        tmp_path, rollover_tool, isolated_environment, process_runner, arguments
    )

    assert_parser_failure(
        result,
        tmp_path,
        "invalid option: --issuer-safety-days=\n",
    )


@pytest.mark.parametrize("option", RECOVER_REQUIRED_OPTIONS, ids=option_id)
def test_recover_rejects_empty_required_option(
    tmp_path: Path,
    rollover_tool: Path,
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
    option: str,
) -> None:
    arguments = ["recover", *without_option(RECOVER_CLI[1:], option), option, ""]
    result = run_parser_command(
        tmp_path, rollover_tool, isolated_environment, process_runner, arguments
    )

    assert_parser_failure(result, tmp_path, *empty_option_diagnostic(option))


@pytest.mark.parametrize(
    "arguments",
    [
        [*PREPARE_CLI, "unexpected"],
        [*RECOVER_CLI, "unexpected"],
    ],
    ids=("prepare", "recover"),
)
def test_subcommand_rejects_positional_argument(
    tmp_path: Path,
    rollover_tool: Path,
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
    arguments: list[str],
) -> None:
    result = run_parser_command(
        tmp_path, rollover_tool, isolated_environment, process_runner, arguments
    )

    assert_parser_failure(result, tmp_path, "invalid argument: unexpected\n")


@pytest.mark.parametrize(
    ("option", "value"),
    [
        ("--root-name", "Root"),
        ("--root-days", "2"),
        ("--private-repo", "/tmp/private"),
    ],
    ids=option_id,
)
def test_intermediate_prepare_rejects_root_only_option(
    tmp_path: Path,
    rollover_tool: Path,
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
    option: str,
    value: str,
) -> None:
    result = run_parser_command(
        tmp_path,
        rollover_tool,
        isolated_environment,
        process_runner,
        [*PREPARE_CLI, option, value],
    )

    assert result.status == 1
    assert result.stdout == ""
    assert result.stderr == (
        "[ERROR] --root-name, --root-days, and --private-repo are forbidden "
        "for intermediate preparation\n"
    )
    assert_parser_paths_untouched(tmp_path)


@pytest.mark.parametrize("option", RECOVER_FORBIDDEN_OPTIONS, ids=option_id)
def test_recover_rejects_prepare_option(
    tmp_path: Path,
    rollover_tool: Path,
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
    option: str,
) -> None:
    result = run_parser_command(
        tmp_path,
        rollover_tool,
        isolated_environment,
        process_runner,
        [*RECOVER_CLI, option, "value"],
    )

    assert_parser_failure(result, tmp_path, f"invalid option: {option}\n")


@pytest.mark.parametrize("option", PREPARE_FORBIDDEN_OPTIONS, ids=option_id)
def test_prepare_rejects_recover_option(
    tmp_path: Path,
    rollover_tool: Path,
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
    option: str,
) -> None:
    result = run_parser_command(
        tmp_path,
        rollover_tool,
        isolated_environment,
        process_runner,
        [*PREPARE_CLI, option, "value"],
    )

    assert_parser_failure(result, tmp_path, f"invalid option: {option}\n")
