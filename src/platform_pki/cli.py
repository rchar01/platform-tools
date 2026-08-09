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


def _handler(route: tuple[str, ...]):
    if route == ("init",):
        from .init import initialize

        return initialize
    if route == ("inventory-install",):
        from .inventory_install import install_inventory

        return install_inventory
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
    if route == ("list-expiry",):
        from .list_expiry import list_expiry

        return list_expiry
    if route == ("print-cert",):
        from .print_cert import print_certificate

        return print_certificate
    if route == ("service-verify",):
        from .service_verify import verify_service

        return verify_service
    return None


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
    if route == ("init",) and not unified:
        print(
            f"{name} - Create the local outside-Git PKI working directory\n\n"
            f"{_color('Usage:', '1')}\n"
            f"  {name} [OPTIONS]\n"
            f"  {name} --help | -h\n"
            f"  {name} --version | -v\n\n"
            f"{_color('Options:', '1')}\n"
            f"  {_color('--namespace PATH', '35')}\n"
            "    Platform namespace root\n\n"
            f"  {_color('--pki-dir PATH', '35')}\n"
            "    PKI directory\n\n"
            f"  {_color('--force', '35')}\n"
            "    Refresh the inventory example\n\n"
            f"  {_color('--help, -h', '35')}\n"
            "    Show this help\n\n"
            f"  {_color('--version, -v', '35')}\n"
            "    Show version number\n\n"
            f"{_color('Examples:', '1')}\n"
            f"  {name}\n"
            f"  {name} --namespace /tmp/platform-pki-test\n\n"
            "The namespace defaults to platform-infrastructure under the XDG\n"
            "configuration home. The PKI directory defaults to <namespace>/pki.\n"
            "--force never overwrites active inventory, CA keys, certificates, or database state.\n\n",
            end="",
        )
        return
    if route == ("inventory-install",) and not unified:
        print(
            f"{name} - Install private-Git service inventory into local PKI state\n\n"
            f"{_color('Usage:', '1')}\n"
            f"  {name} [OPTIONS]\n"
            f"  {name} --help | -h\n"
            f"  {name} --version | -v\n\n"
            f"{_color('Options:', '1')}\n"
            f"  {_color('--private-repo PATH', '35')}\n"
            "    Private repository path\n"
            "    Default: ../platform-private\n\n"
            f"  {_color('--namespace PATH', '35')}\n"
            "    Platform namespace root\n\n"
            f"  {_color('--pki-dir PATH', '35')}\n"
            "    PKI directory\n\n"
            f"  {_color('--help, -h', '35')}\n"
            "    Show this help\n\n"
            f"  {_color('--version, -v', '35')}\n"
            "    Show version number\n\n"
            f"{_color('Examples:', '1')}\n"
            f"  {name}\n"
            f"  {name} --private-repo /srv/platform-private\n\n"
            "The source is <private-repo>/pki/services.yml. Relative repository paths\n"
            "resolve from the physical current directory. The destination is atomically\n"
            "installed as mode 600 and is never linked to the source.\n"
            "Legacy layouts are accepted so inventory can be installed before migration.\n\n",
            end="",
        )
        return
    if route == ("list-expiry",) and not unified:
        print(
            f"{name} - List expiry dates for generated service certificates\n\n"
            f"{_color('Usage:', '1')}\n"
            f"  {name} [OPTIONS]\n"
            f"  {name} --help | -h\n"
            f"  {name} --version | -v\n\n"
            f"{_color('Options:', '1')}\n"
            f"  {_color('--namespace PATH', '35')}\n"
            "    Platform namespace root\n\n"
            f"  {_color('--pki-dir PATH', '35')}\n"
            "    PKI directory\n\n"
            f"  {_color('--warn-days DAYS', '35')}\n"
            "    Warning threshold\n"
            "    Default: 90\n\n"
            f"  {_color('--critical-days DAYS', '35')}\n"
            "    Critical threshold\n"
            "    Default: 30\n\n"
            f"  {_color('--help, -h', '35')}\n"
            "    Show this help\n\n"
            f"  {_color('--version, -v', '35')}\n"
            "    Show version number\n\n"
            f"{_color('Examples:', '1')}\n"
            f"  {name}\n"
            f"  {name} --warn-days 90 --critical-days 30\n\n"
            "The namespace defaults to platform-infrastructure under the XDG\n"
            "configuration home. The PKI directory defaults to <namespace>/pki.\n"
            "Legacy singleton CA state must be migrated before this command can run.\n\n"
            "Certificate status exit codes:\n"
            "  0 all OK\n"
            "  1 warning threshold reached\n"
            "  2 critical threshold reached\n"
            "  3 generated certificate missing\n\n"
            "Parser and configuration errors exit 1.\n",
            end="",
        )
        return
    if route == ("print-cert",) and not unified:
        print(
            f"{name} - Print readable details for a generated service certificate\n\n"
            f"{_color('Usage:', '1')}\n"
            f"  {name} SERVICE [OPTIONS]\n"
            f"  {name} --help | -h\n"
            f"  {name} --version | -v\n\n"
            f"{_color('Options:', '1')}\n"
            f"  {_color('--namespace PATH', '35')}\n"
            "    Platform namespace root\n\n"
            f"  {_color('--pki-dir PATH', '35')}\n"
            "    PKI directory\n\n"
            f"  {_color('--help, -h', '35')}\n"
            "    Show this help\n\n"
            f"  {_color('--version, -v', '35')}\n"
            "    Show version number\n\n"
            f"{_color('Arguments:', '1')}\n"
            f"  {_color('SERVICE', '34')}\n"
            "    Inventory service name\n\n"
            f"{_color('Examples:', '1')}\n"
            f"  {name} platform-example\n"
            f"  {name} platform-example --pki-dir /tmp/platform-pki\n\n"
            "The namespace defaults to platform-infrastructure under the XDG\n"
            "configuration home. The PKI directory defaults to <namespace>/pki.\n"
            "Legacy singleton CA state must be migrated before this command can run.\n",
            end="",
        )
        return
    if route == ("service-verify",) and not unified:
        print(
            f"{name} - Verify a generated service certificate\n\n"
            f"{_color('Usage:', '1')}\n"
            f"  {name} SERVICE [OPTIONS]\n"
            f"  {name} --help | -h\n"
            f"  {name} --version | -v\n\n"
            f"{_color('Options:', '1')}\n"
            f"  {_color('--namespace PATH', '35')}\n"
            "    Platform namespace root\n\n"
            f"  {_color('--pki-dir PATH', '35')}\n"
            "    PKI directory\n\n"
            f"  {_color('--min-days DAYS', '35')}\n"
            "    Required remaining validity\n"
            "    Default: 30\n\n"
            f"  {_color('--help, -h', '35')}\n"
            "    Show this help\n\n"
            f"  {_color('--version, -v', '35')}\n"
            "    Show version number\n\n"
            f"{_color('Arguments:', '1')}\n"
            f"  {_color('SERVICE', '34')}\n"
            "    Inventory service name\n\n"
            f"{_color('Examples:', '1')}\n"
            f"  {name} platform-example\n"
            f"  {name} platform-example --min-days 60\n\n"
            "Verifies chain trust, private-key match, CA:false, serverAuth, inventory\n"
            "SANs, and remaining validity. The PKI directory defaults to <namespace>/pki.\n"
            "Inventory entries with key_custody: host-local fail closed here; use\n"
            "platform-pki-csr-candidate verify with an exact request ID.\n"
            "Legacy singleton CA state must be migrated before this command can run.\n",
            end="",
        )
        return
    if route == ("export-ansible",) and not unified:
        print(
            f"{name} - Export generated PKI files into an Ansible-consumable layout\n\n"
            f"{_color('Usage:', '1')}\n"
            f"  {name} [SERVICES...] [OPTIONS]\n"
            f"  {name} --help | -h\n"
            f"  {name} --version | -v\n\n"
            f"{_color('Options:', '1')}\n"
            f"  {_color('--namespace PATH', '35')}\n"
            "    Platform namespace root\n\n"
            f"  {_color('--pki-dir PATH', '35')}\n"
            "    PKI directory\n\n"
            f"  {_color('--export-dir PATH', '35')}\n"
            "    Export directory\n\n"
            f"  {_color('--force', '35')}\n"
            "    Replace an existing trusted export directory\n\n"
            f"  {_color('--help, -h', '35')}\n"
            "    Show this help\n\n"
            f"  {_color('--version, -v', '35')}\n"
            "    Show version number\n\n"
            f"{_color('Arguments:', '1')}\n"
            f"  {_color('SERVICES...', '34')}\n"
            "    Inventory service names; defaults to all generated services\n\n"
            f"{_color('Examples:', '1')}\n"
            f"  {name} --force\n"
            f"  {name} platform-example --force\n\n"
            "The export contains service private keys. Custom export directories must be\n"
            "absolute and pass ownership, permission, and symlink safety checks.\n"
            "Explicit host-local service selection fails; all-service export skips\n"
            "host-local inventory entries because this export is managed-key-only.\n"
            "Legacy singleton CA state must be migrated before this command can run.\n\n",
            end="",
        )
        return
    if route == ("custody-report",) and not unified:
        print(
            f"{name} - Report PKI encryption, custody, and backup-policy findings\n\n"
            f"{_color('Usage:', '1')}\n"
            f"  {name} [OPTIONS]\n"
            f"  {name} --help | -h\n"
            f"  {name} --version | -v\n\n"
            f"{_color('Options:', '1')}\n"
            f"  {_color('--namespace PATH', '35')}\n"
            "    Platform namespace root\n\n"
            f"  {_color('--pki-dir PATH', '35')}\n"
            "    PKI directory\n\n"
            f"  {_color('--format VALUE', '35')}\n"
            "    Report format\n"
            "    Default: text\n\n"
            f"  {_color('--help, -h', '35')}\n"
            "    Show this help\n\n"
            f"  {_color('--version, -v', '35')}\n"
            "    Show version number\n\n"
            f"{_color('Examples:', '1')}\n"
            f"  {name}\n"
            f"  {name} --format json\n\n"
            "The report inspects managed PKI paths, file metadata, storage ancestry, age\n"
            "headers, and only the first PEM header line of validated private-key files.\n"
            "It never decrypts, parses, hashes, copies, or prints private-key content.\n\n"
            "Report exit codes:\n"
            "  0 no structural custody findings\n"
            "  1 parser, configuration, or unsafe-layout error\n"
            "  2 one or more custody or encryption findings\n\n",
            end="",
        )
        return
    if route == ("backup",) and not unified:
        print(
            f"{name} - Create a backup archive of the outside-Git PKI directory\n\n"
            f"{_color('Usage:', '1')}\n"
            f"  {name} [OPTIONS]\n"
            f"  {name} --help | -h\n"
            f"  {name} --version | -v\n\n"
            f"{_color('Options:', '1')}\n"
            f"  {_color('--namespace PATH', '35')}\n"
            "    Platform namespace root\n\n"
            f"  {_color('--pki-dir PATH', '35')}\n"
            "    PKI directory\n\n"
            f"  {_color('--backup-dir PATH', '35')}\n"
            "    Backup output directory\n\n"
            f"  {_color('--age-recipient VALUE (repeatable)', '35')}\n"
            "    Encrypt to an age recipient\n\n"
            f"  {_color('--allow-plain-backup', '35')}\n"
            "    Create an unencrypted .tar.gz archive\n\n"
            f"  {_color('--help, -h', '35')}\n"
            "    Show this help\n\n"
            f"  {_color('--version, -v', '35')}\n"
            "    Show version number\n\n"
            f"{_color('Examples:', '1')}\n"
            f"  {name} --age-recipient age1example\n"
            f"  {name} --allow-plain-backup\n\n"
            "Encryption with age is the default. Without a recipient, age prompts in\n"
            "passphrase mode. Plain archives require --allow-plain-backup and still\n"
            "contain private keys and other secrets.\n\n",
            end="",
        )
        return
    if route == ("ca-passphrase-verify",) and not unified:
        print(
            f"{name} - Verify active CA key passphrases and certificate matches\n\n"
            f"{_color('Usage:', '1')}\n"
            f"  {name} [OPTIONS]\n"
            f"  {name} --help | -h\n"
            f"  {name} --version | -v\n\n"
            f"{_color('Options:', '1')}\n"
            f"  {_color('--namespace PATH', '35')}\n"
            "    Platform namespace root\n\n"
            f"  {_color('--pki-dir PATH', '35')}\n"
            "    PKI directory\n\n"
            f"  {_color('--root-pass-file PATH', '35')}\n"
            "    Restricted file containing the active root key passphrase\n\n"
            f"  {_color('--intermediate-pass-file PATH', '35')}\n"
            "    Restricted file containing the active intermediate key passphrase\n\n"
            f"  {_color('--help, -h', '35')}\n"
            "    Show this help\n\n"
            f"  {_color('--version, -v', '35')}\n"
            "    Show version number\n\n"
            f"{_color('Examples:', '1')}\n"
            f"  {name} --root-pass-file\n"
            "  /run/secrets/platform-pki-root-pass\n"
            f"  {name} --intermediate-pass-file\n"
            "  /run/secrets/platform-pki-intermediate-pass\n"
            f"  {name} --root-pass-file\n"
            "  /run/secrets/platform-pki-root-pass --intermediate-pass-file\n"
            "  /run/secrets/platform-pki-intermediate-pass\n\n"
            "At least one passphrase-file option is required. The command validates the\n"
            "active encrypted private key, derives its public key, and proves that it\n"
            "matches the active certificate. Passphrases are supplied to OpenSSL through\n"
            "inherited file descriptors and are never placed in argv, the environment,\n"
            "or output. No receipt or persistent verification state is written.\n\n"
            "Passphrase files must be current-user-owned, singly linked, non-symlink\n"
            "regular files with mode 600 or stricter and a first line of at least 16\n"
            "characters containing non-whitespace content. Legacy singleton CA state\n"
            "must be migrated before this command can run.\n\n",
            end="",
        )
        return
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
