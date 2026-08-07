import os
import sys
from collections.abc import Sequence

from ._version import VERSION  # type: ignore[import-not-found]
from .compat import COMMANDS, COMPATIBILITY_COMMANDS, invocation_name
from .errors import ApplicationError, render_error
from .parser import (
    ROUTE_SPECS,
    ParserError,
    leading_action,
    parse_route,
    render_route_help,
)


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


def _command_help(
    name: str,
    route: tuple[str, ...],
    *,
    subcommands: tuple[str, ...] = (),
) -> str:
    route_text = " ".join(route)
    invocation = f"{name} {route_text}" if route_text else name
    if subcommands:
        invocation += " COMMAND"
    help_text = (
        f"{_color('Usage:', '1;33')} {invocation} [OPTIONS]\n\n"
    )
    if subcommands:
        help_text += f"{_color('Commands:', '1;33')}\n"
        help_text += "\n".join(f"  {subcommand}" for subcommand in subcommands)
        help_text += "\n\n"
    return help_text + f"{_color('Options:', '1;33')}\n  -h, --help  Show this help\n"


def _error(message: str) -> int:
    error = ApplicationError(message)
    print(render_error(error), file=sys.stderr, end="")
    return error.status


def _print_route_help(name: str, route: tuple[str, ...], *, unified: bool) -> None:
    text = render_route_help(name, ROUTE_SPECS[route], compatibility=not unified)
    text = text.replace("Usage:", _color("Usage:", "1;33"), 1)
    text = text.replace("Options:", _color("Options:", "1;33"), 1)
    print(text, end="")


def _parser_error(error: ParserError) -> int:
    print(error.render(), file=sys.stderr, end="")
    return 1


def _dispatch(name: str, command: str, arguments: list[str], *, unified: bool) -> int:
    nested = COMMANDS[command]
    if nested and arguments and leading_action(arguments[0], version=False) == "help":
        route = (command,) if unified else ()
        print(_command_help(name, route, subcommands=nested), end="")
        return 0

    route = (command,)
    if nested:
        if not arguments:
            return _error(f"A subcommand is required for {command}")
        leaf = arguments.pop(0)
        if leaf not in nested:
            return _error(f"Unknown {command} subcommand: {leaf}")
        route = (command, leaf)
        if arguments and leading_action(arguments[0], version=False) == "help":
            _print_route_help(name, route, unified=unified)
            return 0

    if not nested and arguments and leading_action(arguments[0], version=False) == "help":
        _print_route_help(name, route, unified=unified)
        return 0
    try:
        parse_route(
            route,
            arguments,
            interactive=sys.stdin.isatty() and sys.stdout.isatty(),
        )
    except ParserError as error:
        return _parser_error(error)
    return _error(f"Command is not available in the Python foundation: {' '.join(route)}")


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    name = invocation_name(sys.argv[0])
    unified = name == "platform-pki"
    compatibility_command = COMPATIBILITY_COMMANDS.get(name)
    if not unified and compatibility_command is None:
        return _error(f"Unsupported invocation name: {name}")

    action = leading_action(arguments[0], version=True) if arguments else None
    if action == "help":
        if unified:
            print(_root_help(name), end="")
        else:
            assert compatibility_command is not None
            nested = COMMANDS[compatibility_command]
            if nested:
                print(
                    _command_help(name, (), subcommands=nested),
                    end="",
                )
            else:
                _print_route_help(name, (compatibility_command,), unified=False)
        return 0
    if action == "version":
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
