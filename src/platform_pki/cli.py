import os
import sys
from collections.abc import Sequence

from ._version import VERSION  # type: ignore[import-not-found]
from .compat import COMMANDS, COMPATIBILITY_COMMANDS, invocation_name


_HELP_FLAGS = {"-h", "--help"}
_VERSION_FLAGS = {"-v", "--version"}


def _color(text: str, code: str) -> str:
    if sys.stdout.isatty() and not os.environ.get("NO_COLOR"):
        return f"\033[{code}m{text}\033[0m"
    return text


def _root_help(name: str) -> str:
    commands = "\n".join(f"  {command}" for command in COMMANDS)
    return (
        f"{_color('Usage:', '1;33')} {name} COMMAND [OPTIONS]\n\n"
        f"{_color('Commands:', '1;33')}\n{commands}\n\n"
        f"{_color('Options:', '1;33')}\n"
        "  -h, --help     Show this help\n"
        "  -v, --version  Show version\n"
    )


def _command_help(name: str, route: tuple[str, ...], *, has_subcommands: bool = False) -> str:
    route_text = " ".join(route)
    invocation = f"{name} {route_text}" if route_text else name
    if has_subcommands:
        invocation += " COMMAND"
    return (
        f"{_color('Usage:', '1;33')} {invocation} [OPTIONS]\n\n"
        f"{_color('Options:', '1;33')}\n"
        "  -h, --help  Show this help\n"
    )


def _error(message: str) -> int:
    print(f"[ERROR] {message}", file=sys.stderr)
    return 1


def _dispatch(name: str, command: str, arguments: list[str], *, unified: bool) -> int:
    nested = COMMANDS[command]
    if arguments and arguments[0] in _HELP_FLAGS:
        route = (command,) if unified else ()
        print(_command_help(name, route, has_subcommands=bool(nested)), end="")
        return 0

    route = (command,)
    if nested:
        if not arguments:
            return _error(f"A subcommand is required for {command}")
        leaf = arguments.pop(0)
        if leaf not in nested:
            return _error(f"Unknown {command} subcommand: {leaf}")
        route = (command, leaf)
        if arguments and arguments[0] in _HELP_FLAGS:
            display_route = route if unified else (leaf,)
            print(_command_help(name, display_route), end="")
            return 0

    if arguments:
        return _error(f"Unsupported argument: {arguments[0]}")
    return _error(f"Command is not available in the Python foundation: {' '.join(route)}")


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    name = invocation_name(sys.argv[0])
    unified = name == "platform-pki"
    compatibility_command = COMPATIBILITY_COMMANDS.get(name)
    if not unified and compatibility_command is None:
        return _error(f"Unsupported invocation name: {name}")

    if arguments and arguments[0] in _HELP_FLAGS:
        if unified:
            print(_root_help(name), end="")
        else:
            assert compatibility_command is not None
            print(
                _command_help(
                    name,
                    (),
                    has_subcommands=bool(COMMANDS[compatibility_command]),
                ),
                end="",
            )
        return 0
    if arguments and arguments[0] in _VERSION_FLAGS:
        print(f"{name} {VERSION}")
        return 0

    if unified:
        if not arguments:
            return _error("A command is required")
        command = arguments.pop(0)
        if command not in COMMANDS:
            return _error(f"Unknown command: {command}")
        return _dispatch(name, command, arguments, unified=True)

    assert compatibility_command is not None
    return _dispatch(name, compatibility_command, arguments, unified=False)
