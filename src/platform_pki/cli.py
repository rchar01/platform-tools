import os
import sys
from collections.abc import Sequence

try:
    from ._version import VERSION  # type: ignore[import-not-found]
except ModuleNotFoundError as error:
    if error.name != f"{__package__}._version":
        raise
    with open(
        os.path.join(os.path.dirname(__file__), "..", "..", "VERSION"),
        encoding="ascii",
    ) as version_file:
        VERSION = version_file.read().strip()
from .errors import ApplicationError, render_error
from .parser import (
    ROUTE_SPECS,
    ParserError,
    leading_action,
    parse_route,
    render_route_help,
)
from .routes import COMMANDS


_NAME = "platform-pki"


def _handler(route: tuple[str, ...]):
    if route == ("init",):
        from .init import initialize

        return initialize
    if route == ("inventory-install",):
        from .inventory_install import install_inventory

        return install_inventory
    if route == ("csr-trust-install",):
        from .csr_trust_install import install_csr_trust

        return install_csr_trust
    if route == ("csr-recover",):
        from .csr_recover import recover_csr

        return recover_csr
    if route in (("offline-csr", "approve"), ("offline-csr", "sign")):
        from .offline_csr import offline_csr

        return offline_csr
    if route in (
        ("csr-candidate", "verify"),
        ("csr-candidate", "finalize"),
        ("csr-candidate", "abandon"),
    ):
        from .csr_candidate import csr_candidate

        return csr_candidate
    if route in (("certificate-export", "publish"), ("certificate-export", "resolve")):
        from .certificate_export import certificate_export

        return certificate_export
    if route in (("csr-outcome", "publish"), ("csr-outcome", "resolve")):
        from .csr_outcome import csr_outcome

        return csr_outcome
    if route[0] == "direct-exchange":
        from .direct_exchange import direct_exchange

        return direct_exchange
    if route[0] == "gitlab-package":
        from .gitlab_package import gitlab_package

        return gitlab_package
    if route == ("export-ansible",):
        from .export_ansible import export_ansible

        return export_ansible
    if route == ("backup",):
        from .backup import backup

        return backup
    if route == ("custody-report",):
        from .custody_report import custody_report

        return custody_report
    if route == ("ca-passphrase-verify",):
        from .ca_passphrase_verify import verify_ca_passphrases

        return verify_ca_passphrases
    if route == ("root-create",):
        from .root_create import create_root

        return create_root
    if route == ("intermediate-create",):
        from .intermediate_create import create_intermediate

        return create_intermediate
    if route == ("ca-rollover", "migrate"):
        from .ca_rollover_migrate import migrate_ca_rollover

        return migrate_ca_rollover
    if route == ("ca-rollover", "status"):
        from .ca_rollover_status import ca_rollover_status

        return ca_rollover_status
    if route == ("ca-rollover", "prepare"):
        from .ca_rollover_prepare import prepare_ca_rollover

        return prepare_ca_rollover
    if route == ("ca-rollover", "recover"):
        from .ca_rollover_recover import recover_ca_rollover

        return recover_ca_rollover
    if route == ("list-expiry",):
        from .list_expiry import list_expiry

        return list_expiry
    if route == ("print-cert",):
        from .print_cert import print_certificate

        return print_certificate
    if route == ("service-verify",):
        from .service_verify import verify_service

        return verify_service
    if route == ("service-issue",):
        from .service_issue import issue_service

        return issue_service
    if route == ("service-renew",):
        from .service_issue import renew_service

        return renew_service
    if route == ("service-recover",):
        from .service_recover import recover_service

        return recover_service
    return None


def _color(text: str, code: str) -> str:
    if sys.stdout.isatty() and not os.environ.get("NO_COLOR"):
        return f"\033[{code}m{text}\033[0m"
    return text


def _root_help() -> str:
    commands = "\n".join(f"  {command}" for command in COMMANDS)
    return (
        f"{_color('Usage:', '1;33')} {_NAME} COMMAND [OPTIONS]\n\n"
        f"{_color('Commands:', '1;33')}\n{commands}\n\n"
        f"{_color('Options:', '1;33')}\n"
        "  -h, --help     Show this help\n"
        "  -v, --version  Show version\n"
    )


def _command_help(command: str, subcommands: tuple[str, ...]) -> str:
    help_text = (
        f"{_color('Usage:', '1;33')} {_NAME} {command} COMMAND [OPTIONS]\n\n"
        f"{_color('Commands:', '1;33')}\n"
    )
    help_text += "\n".join(f"  {subcommand}" for subcommand in subcommands)
    return help_text + f"\n\n{_color('Options:', '1;33')}\n  -h, --help  Show this help\n"


def _error(message: str) -> int:
    error = ApplicationError(message)
    print(render_error(error), file=sys.stderr, end="")
    return error.status


def _print_route_help(route: tuple[str, ...]) -> None:
    text = render_route_help(ROUTE_SPECS[route])
    text = text.replace("Usage:", _color("Usage:", "1;33"), 1)
    text = text.replace("Options:", _color("Options:", "1;33"), 1)
    print(text, end="")


def _parser_error(error: ParserError) -> int:
    print(error.render(), file=sys.stderr, end="")
    return 1


def _positional_prefix_requests_help(
    route: tuple[str, ...], arguments: list[str]
) -> bool:
    if len(arguments) < 2:
        return False
    help_index = next(
        (
            index
            for index, argument in enumerate(arguments)
            if leading_action(argument, version=False) == "help"
        ),
        None,
    )
    if help_index is None or help_index == 0:
        return False
    prefix = arguments[:help_index]
    if any(argument.startswith("-") for argument in prefix):
        return False
    positionals = ROUTE_SPECS[route].positionals
    return bool(positionals) and (
        positionals[-1].repeatable or len(prefix) <= len(positionals)
    )


def _dispatch(command: str, arguments: list[str]) -> int:
    nested = COMMANDS[command]
    if nested and arguments and leading_action(arguments[0], version=False) == "help":
        print(_command_help(command, nested), end="")
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
            _print_route_help(route)
            return 0

    if _positional_prefix_requests_help(route, arguments):
        _print_route_help(route)
        return 0
    if not nested and arguments and leading_action(arguments[0], version=False) == "help":
        _print_route_help(route)
        return 0
    try:
        parsed = parse_route(
            route,
            arguments,
            interactive=sys.stdin.isatty() and sys.stdout.isatty(),
        )
    except ParserError as error:
        return _parser_error(error)
    handler = _handler(route)
    if handler is None:
        return _error(f"Command is not available in the Python foundation: {' '.join(route)}")
    try:
        return handler(parsed)
    except ApplicationError as error:
        print(render_error(error), file=sys.stderr, end="")
        return error.status


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    action = leading_action(arguments[0], version=True) if arguments else None
    if action == "help":
        print(_root_help(), end="")
        return 0
    if action == "version":
        print(f"{_NAME} {VERSION}")
        return 0
    if not arguments:
        return _error("A command is required")
    command = arguments.pop(0)
    if command not in COMMANDS:
        return _error(f"Unknown command: {command}")
    return _dispatch(command, arguments)
