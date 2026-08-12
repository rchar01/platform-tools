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
    if route == ("csr-trust-install",):
        from .csr_trust_install import install_csr_trust

        return install_csr_trust
    if route == ("csr-recover",):
        from .csr_recover import recover_csr

        return recover_csr
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
    if len(route) == 2 and route[0] == "csr-candidate" and not unified:
        action = route[1]
        descriptions = {
            "verify": "Verify one exact candidate and report accepted historical state",
            "finalize": "Accept authenticated activation and validation evidence",
            "abandon": "Record authenticated non-activation or rollback evidence",
        }
        options = (
            f"  {_color('--request-id ID (required)', '35')}\n"
            "    Exact 32-character lowercase hexadecimal CSR request ID\n\n"
        )
        if action == "verify":
            options += (
                f"  {_color('--format FORMAT', '35')}\n"
                "    Output format\n"
                "    Allowed: text, json\n"
                "    Default: text\n\n"
            )
        else:
            options += (
                f"  {_color('--artifact-manifest-sha256 DIGEST (required)', '35')}\n"
                "    Exact lowercase SHA-256 digest of the export artifact manifest\n\n"
                f"  {_color('--evidence-file PATH (required)', '35')}\n"
                "    Exact canonical deployment evidence record\n\n"
                f"  {_color('--evidence-signature PATH (required)', '35')}\n"
                "    Detached OpenSSH deployment evidence signature\n\n"
                f"  {_color('--yes', '35')}\n"
                "    Confirm the exact decision without a TTY\n\n"
            )
        print(
            f"{name} {action} - {descriptions[action]}\n\n"
            f"{_color('Usage:', '1')}\n"
            f"  {name} {action} SERVICE [OPTIONS]\n"
            f"  {name} {action} --help | -h\n\n"
            f"{_color('Options:', '1')}\n"
            f"{options}"
            f"  {_color('--namespace PATH', '35')}\n"
            "    Platform namespace root\n\n"
            f"  {_color('--pki-dir PATH', '35')}\n"
            "    PKI directory\n\n"
            f"  {_color('--help, -h', '35')}\n"
            "    Show this help\n\n"
            f"{_color('Arguments:', '1')}\n"
            f"  {_color('SERVICE', '34')}\n"
            "    Exact inventory service\n\n",
            end="",
        )
        return
    if route in (
        ("certificate-export", "publish"),
        ("certificate-export", "resolve"),
    ) and not unified:
        action = route[1]
        if action == "publish":
            description = "Publish one exact pending CSR response as an immutable export"
            options = (
                f"  {_color('--request-id ID (required)', '35')}\n"
                "    Exact 32-character lowercase hexadecimal CSR request ID\n\n"
                f"  {_color('--namespace PATH', '35')}\n"
                "    Platform namespace root\n\n"
                f"  {_color('--pki-dir PATH', '35')}\n"
                "    PKI directory\n\n"
            )
            example = (
                f"  {name} publish platform-example --request-id\n"
                "  0123456789abcdef0123456789abcdef\n"
            )
        else:
            description = "Resolve one digest-pinned immutable certificate export"
            options = (
                f"  {_color('--request-id ID (required)', '35')}\n"
                "    Exact 32-character lowercase hexadecimal CSR request ID\n\n"
                f"  {_color('--manifest-sha256 DIGEST (required)', '35')}\n"
                "    Exact lowercase SHA-256 digest of the artifact manifest\n\n"
                f"  {_color('--format FORMAT', '35')}\n"
                "    Output format\n"
                "    Allowed: path, json\n"
                "    Default: path\n\n"
                f"  {_color('--namespace PATH', '35')}\n"
                "    Platform namespace root\n\n"
                f"  {_color('--pki-dir PATH', '35')}\n"
                "    PKI directory\n\n"
            )
            example = (
                f"  {name} resolve platform-example --request-id\n"
                "  0123456789abcdef0123456789abcdef --manifest-sha256\n"
                "  0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n"
            )
        print(
            f"{name} {action} - {description}\n\n"
            f"{_color('Usage:', '1')}\n"
            f"  {name} {action} SERVICE [OPTIONS]\n"
            f"  {name} {action} --help | -h\n\n"
            f"{_color('Options:', '1')}\n"
            f"{options}"
            f"  {_color('--help, -h', '35')}\n"
            "    Show this help\n\n"
            f"{_color('Arguments:', '1')}\n"
            f"  {_color('SERVICE', '34')}\n"
            "    Exact inventory service\n\n"
            f"{_color('Examples:', '1')}\n"
            f"{example}\n",
            end="",
        )
        return
    if route == ("csr-trust-install",) and not unified:
        print(
            f"{name} - Install reviewed host-local CSR signing trust\n\n"
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
            "The source is <private-repo>/pki/csr-trust. Schema 1 contains exactly policy,\n"
            "requesters.allowed_signers, approvers.allowed_signers, and\n"
            "responses.allowed_signers. Schema 2 adds exactly deployers.allowed_signers\n"
            "and is required for candidate finalization or abandonment. The complete\n"
            "validated snapshot is atomically installed under\n"
            "<pki-dir>/inventory/csr-trust while holding the lifecycle, root, intermediate,\n"
            "and inventory locks. Initial schema-2 installation is allowed when no\n"
            "candidate is pending, and identical content remains a no-op. Any actual change\n"
            "involving schema 2 is rejected while a retained candidate lacks an\n"
            "authenticated finalized or abandoned outcome. No private key is installed.\n\n",
            end="",
        )
        return
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
    if route == ("service-issue",) and not unified:
        print(
            f"{name} - Issue a service certificate from PKI inventory\n\n"
            f"{_color('Usage:', '1')}\n"
            f"  {name} SERVICE [OPTIONS]\n"
            f"  {name} --help | -h\n"
            f"  {name} --version | -v\n\n"
            f"{_color('Options:', '1')}\n"
            f"  {_color('--namespace PATH', '35')}\n"
            "    Platform namespace root\n\n"
            f"  {_color('--pki-dir PATH', '35')}\n"
            "    PKI directory\n\n"
            f"  {_color('--days DAYS', '35')}\n"
            "    Service certificate lifetime\n\n"
            f"  {_color('--issuer-safety-days DAYS', '35')}\n"
            "    Required validity margin before the intermediate expires\n"
            "    Default: 1\n\n"
            f"  {_color('--intermediate-pass-file PATH', '35')}\n"
            "    Restricted file containing the encrypted intermediate-key passphrase\n\n"
            f"  {_color('--rotate-key', '35')}\n"
            "    Archive and replace an existing service private key\n\n"
            f"  {_color('--csr-file PATH', '35')}\n"
            "    Host-generated P-384 CSR\n\n"
            f"  {_color('--request-file PATH', '35')}\n"
            "    Canonical authenticated CSR request manifest\n\n"
            f"  {_color('--request-signature PATH', '35')}\n"
            "    Detached OpenSSH request signature\n\n"
            f"  {_color('--approval-file PATH', '35')}\n"
            "    Canonical offline approval manifest\n\n"
            f"  {_color('--approval-signature PATH', '35')}\n"
            "    Detached OpenSSH approval signature\n\n"
            f"  {_color('--response-key PATH', '35')}\n"
            "    Trusted Ed25519 response-signing private key\n\n"
            f"  {_color('--current-cert-file PATH', '35')}\n"
            "    Current host-local certificate (renewal only)\n\n"
            f"  {_color('--help, -h', '35')}\n"
            "    Show this help\n\n"
            f"  {_color('--version, -v', '35')}\n"
            "    Show version number\n\n"
            f"{_color('Arguments:', '1')}\n"
            f"  {_color('SERVICE', '34')}\n"
            "    Inventory service name\n\n"
            f"{_color('Examples:', '1')}\n"
            f"  {name} platform-example\n"
            f"  {name} platform-example --intermediate-pass-file\n"
            "  /run/secrets/platform-pki-intermediate-pass\n\n"
            "The namespace defaults to platform-infrastructure under the XDG\n"
            "configuration home. The PKI directory defaults to <namespace>/pki.\n"
            "The lifetime uses the inventory value, PLATFORM_PKI_SERVICE_DAYS, or 397\n"
            "days, in that order. Existing private keys are reused unless --rotate-key\n"
            "is used. Existing certificates are never overwritten; use\n"
            "platform-pki-service-renew after initial issuance. Passphrase files must be\n"
            "mode 600 or stricter and have a first line of at least 16 characters\n"
            "containing non-whitespace content.\n"
            "Host-local issue and migration require the complete authenticated CSR,\n"
            "request, approval, and response-signing inputs. They publish only a pending\n"
            "certificate candidate and signed response; managed migration state remains.\n"
            "Legacy singleton CA state must be migrated before this command can run.\n\n",
            end="",
        )
        return
    if route == ("service-renew",) and not unified:
        print(
            f"{name} - Renew a service certificate from PKI inventory\n\n"
            f"{_color('Usage:', '1')}\n"
            f"  {name} SERVICE [OPTIONS]\n"
            f"  {name} --help | -h\n"
            f"  {name} --version | -v\n\n"
            f"{_color('Options:', '1')}\n"
            f"  {_color('--namespace PATH', '35')}\n"
            "    Platform namespace root\n\n"
            f"  {_color('--pki-dir PATH', '35')}\n"
            "    PKI directory\n\n"
            f"  {_color('--days DAYS', '35')}\n"
            "    Service certificate lifetime\n\n"
            f"  {_color('--issuer-safety-days DAYS', '35')}\n"
            "    Required validity margin before the intermediate expires\n"
            "    Default: 1\n\n"
            f"  {_color('--intermediate-pass-file PATH', '35')}\n"
            "    Restricted file containing the encrypted intermediate-key passphrase\n\n"
            f"  {_color('--rotate-key', '35')}\n"
            "    Archive and replace the existing service private key\n\n"
            f"  {_color('--csr-file PATH', '35')}\n"
            "    Host-generated P-384 CSR\n\n"
            f"  {_color('--request-file PATH', '35')}\n"
            "    Canonical authenticated CSR request manifest\n\n"
            f"  {_color('--request-signature PATH', '35')}\n"
            "    Detached OpenSSH request signature\n\n"
            f"  {_color('--approval-file PATH', '35')}\n"
            "    Canonical offline approval manifest\n\n"
            f"  {_color('--approval-signature PATH', '35')}\n"
            "    Detached OpenSSH approval signature\n\n"
            f"  {_color('--response-key PATH', '35')}\n"
            "    Trusted Ed25519 response-signing private key\n\n"
            f"  {_color('--current-cert-file PATH', '35')}\n"
            "    Current host-local certificate bound by the request\n\n"
            f"  {_color('--help, -h', '35')}\n"
            "    Show this help\n\n"
            f"  {_color('--version, -v', '35')}\n"
            "    Show version number\n\n"
            f"{_color('Arguments:', '1')}\n"
            f"  {_color('SERVICE', '34')}\n"
            "    Inventory service name\n\n"
            f"{_color('Examples:', '1')}\n"
            f"  {name} platform-example\n"
            f"  {name} platform-example --rotate-key\n\n"
            "The namespace defaults to platform-infrastructure under the XDG\n"
            "configuration home. The PKI directory defaults to <namespace>/pki.\n"
            "The lifetime uses the inventory value, PLATFORM_PKI_SERVICE_DAYS, or 397\n"
            "days, in that order. The existing private key is reused unless --rotate-key\n"
            "is used. Previous service state is archived only when renewal and verification\n"
            "complete successfully. Passphrase files must be mode 600 or stricter and have\n"
            "a first line of at least 16 characters containing non-whitespace content.\n"
            "Host-local renewal requires the complete authenticated CSR, current\n"
            "certificate, request, approval, and response-signing inputs. It publishes\n"
            "only a pending certificate candidate and signed response.\n"
            "Legacy singleton CA state must be migrated before this command can run.\n\n",
            end="",
        )
        return
    if route == ("csr-recover",) and not unified:
        print(
            f"{name} - Recover an authenticated host-local CSR signing transaction\n\n"
            f"{_color('Usage:', '1')}\n"
            f"  {name} [OPTIONS]\n"
            f"  {name} --help | -h\n"
            f"  {name} --version | -v\n\n"
            f"{_color('Options:', '1')}\n"
            f"  {_color('--transaction ID', '35')}\n"
            "    Exact csr-<request-id> transaction\n\n"
            f"  {_color('--response-key PATH', '35')}\n"
            "    Trusted response-signing key when post-commit signing remains\n\n"
            f"  {_color('--namespace PATH', '35')}\n"
            "    Platform namespace root\n\n"
            f"  {_color('--pki-dir PATH', '35')}\n"
            "    PKI directory\n\n"
            f"  {_color('--yes', '35')}\n"
            "    Confirm deterministic recovery without a TTY\n\n"
            f"  {_color('--help, -h', '35')}\n"
            "    Show this help\n\n"
            f"  {_color('--version, -v', '35')}\n"
            "    Show version number\n\n"
            f"{_color('Examples:', '1')}\n"
            f"  {name} --transaction csr-0123456789abcdef0123456789abcdef\n"
            "  --response-key /secure/response_ed25519\n\n"
            "Uncommitted recovery restores only exact partial CA publication and keeps the\n"
            "request and nonce consumed. Committed recovery never rolls back or re-signs;\n"
            "it resumes exact response and pending-candidate publication. Finalization\n"
            "recovery resumes exact immutable-outcome and active-pointer publication from\n"
            "its separate journal. A response key is used only for CSR signing recovery.\n\n",
            end="",
        )
        return
    if route == ("root-create",) and not unified:
        print(
            f"{name} - Create the root CA key and certificate\n\n"
            f"{_color('Usage:', '1')}\n"
            f"  {name} [OPTIONS]\n"
            f"  {name} --help | -h\n"
            f"  {name} --version | -v\n\n"
            f"{_color('Options:', '1')}\n"
            f"  {_color('--namespace PATH', '35')}\n"
            "    Platform namespace root\n\n"
            f"  {_color('--pki-dir PATH', '35')}\n"
            "    PKI directory\n\n"
            f"  {_color('--name CN (required)', '35')}\n"
            "    Root CA common name\n\n"
            f"  {_color('--org ORG (required)', '35')}\n"
            "    Organization name\n\n"
            f"  {_color('--country COUNTRY (required)', '35')}\n"
            "    Country code\n\n"
            f"  {_color('--days DAYS', '35')}\n"
            "    Root CA lifetime\n\n"
            f"  {_color('--root-pass-file PATH', '35')}\n"
            "    Restricted file containing the encrypted-key passphrase\n"
            "    Conflicts: --allow-unencrypted-root-key\n\n"
            f"  {_color('--allow-unencrypted-root-key', '35')}\n"
            "    Create an unencrypted root private key\n"
            "    Conflicts: --root-pass-file\n\n"
            f"  {_color('--force', '35')}\n"
            "    Refuse unproven replacement and direct recovery to the journal workflow\n\n"
            f"  {_color('--help, -h', '35')}\n"
            "    Show this help\n\n"
            f"  {_color('--version, -v', '35')}\n"
            "    Show version number\n\n"
            f"{_color('Examples:', '1')}\n"
            f"  {name} --name \"Platform Example Root CA\" --org \"Platform\n"
            "  Example\" --country PL\n"
            f"  {name} --namespace /tmp/platform-pki-test --name \"Test Root\n"
            "  CA\" --org \"Test\" --country PL --allow-unencrypted-root-key\n\n"
            "The namespace defaults to platform-infrastructure under the XDG\n"
            "configuration home. The PKI directory defaults to <namespace>/pki.\n"
            "The lifetime defaults to PLATFORM_PKI_ROOT_DAYS or 3650 days.\n"
            "Root keys are encrypted unless --allow-unencrypted-root-key is used.\n"
            "Root generation IDs are allocated monotonically. A failed or interrupted\n"
            "bootstrap permanently abandons its reserved ID; a retry uses the next ID.\n"
            "Legacy singleton CA state must be migrated before this command can run.\n"
            "Passphrase files must be mode 600 or stricter and have a first line of at\n"
            "least 16 characters containing non-whitespace content.\n\n",
            end="",
        )
        return
    if route == ("intermediate-create",) and not unified:
        print(
            f"{name} - Create the intermediate CA key, certificate, and CA chain\n\n"
            f"{_color('Usage:', '1')}\n"
            f"  {name} [OPTIONS]\n"
            f"  {name} --help | -h\n"
            f"  {name} --version | -v\n\n"
            f"{_color('Options:', '1')}\n"
            f"  {_color('--namespace PATH', '35')}\n"
            "    Platform namespace root\n\n"
            f"  {_color('--pki-dir PATH', '35')}\n"
            "    PKI directory\n\n"
            f"  {_color('--name CN (required)', '35')}\n"
            "    Intermediate CA common name\n\n"
            f"  {_color('--org ORG (required)', '35')}\n"
            "    Organization name\n\n"
            f"  {_color('--country COUNTRY (required)', '35')}\n"
            "    Country code\n\n"
            f"  {_color('--days DAYS', '35')}\n"
            "    Intermediate CA lifetime\n\n"
            f"  {_color('--issuer-safety-days DAYS', '35')}\n"
            "    Required validity margin before the root expires\n"
            "    Default: 1\n\n"
            f"  {_color('--root-pass-file PATH', '35')}\n"
            "    Restricted file containing the encrypted root-key passphrase\n\n"
            f"  {_color('--intermediate-pass-file PATH', '35')}\n"
            "    Restricted file containing the encrypted intermediate-key passphrase\n"
            "    Conflicts: --allow-unencrypted-intermediate-key\n\n"
            f"  {_color('--allow-unencrypted-intermediate-key', '35')}\n"
            "    Create an unencrypted intermediate private key\n"
            "    Conflicts: --intermediate-pass-file\n\n"
            f"  {_color('--force', '35')}\n"
            "    Refuse unproven replacement and direct recovery to the journal workflow\n\n"
            f"  {_color('--help, -h', '35')}\n"
            "    Show this help\n\n"
            f"  {_color('--version, -v', '35')}\n"
            "    Show version number\n\n"
            f"{_color('Examples:', '1')}\n"
            f"  {name} --name \"Platform Example Intermediate CA\"\n"
            "  --org \"Platform Example\" --country PL\n"
            f"  {name} --namespace /tmp/platform-pki-test --name\n"
            "  \"Test Intermediate CA\" --org Test --country PL\n"
            "  --allow-unencrypted-intermediate-key\n\n"
            "The namespace defaults to platform-infrastructure under the XDG\n"
            "configuration home. The PKI directory defaults to <namespace>/pki.\n"
            "The lifetime defaults to PLATFORM_PKI_INTERMEDIATE_DAYS or 1825 days.\n"
            "Intermediate generation IDs are allocated monotonically under the bootstrap\n"
            "root. A failed or interrupted bootstrap permanently abandons its reserved ID.\n"
            "Legacy singleton CA state must be migrated before this command can run.\n"
            "Intermediate keys are encrypted unless\n"
            "--allow-unencrypted-intermediate-key is used. Passphrase files must be mode\n"
            "600 or stricter and have a first line of at least 16 characters containing\n"
            "non-whitespace content.\n\n",
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


def _print_certificate_export_root_help(name: str) -> None:
    print(
        f"{name} - Publish or resolve an immutable certificate-only CSR export\n\n"
        f"{_color('Usage:', '1')}\n"
        f"  {name} COMMAND\n"
        f"  {name} [COMMAND] --help | -h\n"
        f"  {name} --version | -v\n\n"
        f"{_color('Commands:', '1')}\n"
        f"  {_color('publish', '32')}   Publish one exact pending CSR response as an immutable export\n"
        f"  {_color('resolve', '32')}   Resolve one digest-pinned immutable certificate export\n\n"
        f"{_color('Options:', '1')}\n"
        f"  {_color('--help, -h', '35')}\n"
        "    Show this help\n\n"
        f"  {_color('--version, -v', '35')}\n"
        "    Show version number\n\n"
        "Publication copies only an authenticated pending CSR certificate response.\n"
        "Exports are unfinalized and contain no private key. Resolution requires the\n"
        "exact service, request ID, and manifest digest; it never infers current or\n"
        "latest state and performs no deployment, activation, or finalization.\n\n",
        end="",
    )


def _print_candidate_root_help(name: str) -> None:
    print(
        f"{name} - Verify, finalize, or abandon authenticated CSR candidate evidence\n\n"
        f"{_color('Usage:', '1')}\n"
        f"  {name} COMMAND\n"
        f"  {name} [COMMAND] --help | -h\n"
        f"  {name} --version | -v\n\n"
        f"{_color('Commands:', '1')}\n"
        f"  {_color('verify', '32')}     Verify one exact candidate and report accepted historical state\n"
        f"  {_color('finalize', '32')}   Accept authenticated activation and validation evidence\n"
        f"  {_color('abandon', '32')}    Record authenticated non-activation or rollback evidence\n\n"
        f"{_color('Options:', '1')}\n"
        f"  {_color('--help, -h', '35')}\n"
        "    Show this help\n\n"
        f"  {_color('--version, -v', '35')}\n"
        "    Show version number\n\n"
        "Verification reports accepted historical evidence and never claims current\n"
        "live state. Finalization verifies bounded-time authenticated evidence but\n"
        "performs no deployment. Abandonment is not revocation. Candidate, response,\n"
        "replay, signing transaction, export, managed keys, and managed exports remain.\n\n",
        end="",
    )


def _print_rollover_root_help(name: str) -> None:
    print(
        f"{name} - Prepare or inspect generation-aware CA rollover state\n\n"
        f"{_color('Usage:', '1')}\n"
        f"  {name} COMMAND\n"
        f"  {name} [COMMAND] --help | -h\n"
        f"  {name} --version | -v\n\n"
        f"{_color('Commands:', '1')}\n"
        f"  {_color('migrate', '32')}   Move a verified legacy CA layout into generation g1 and g1-i1\n"
        f"  {_color('status', '32')}    Report active, candidate, retired, or recovery-required CA state\n"
        f"  {_color('prepare', '32')}   Prepare an immutable root or intermediate rollover candidate\n"
        f"  {_color('recover', '32')}   Resume migration or terminal cleanup, or roll back the journaled transaction\n\n"
        f"{_color('Options:', '1')}\n"
        f"  {_color('--help, -h', '35')}\n"
        "    Show this help\n\n"
        f"  {_color('--version, -v', '35')}\n"
        "    Show version number\n\n"
        "This milestone implements migration, candidate preparation, recovery, and status.\n"
        "activate, acknowledge, rollback, retire, and complete remain unavailable until\n"
        "the immutable export and evidence milestone is implemented.\n\n",
        end="",
    )


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

    if (
        route in (("service-issue",), ("service-renew",))
        and len(arguments) >= 2
        and not arguments[0].startswith("-")
        and leading_action(arguments[1], version=False) == "help"
    ):
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
                if compatibility_command == "certificate-export":
                    _print_certificate_export_root_help(name)
                elif compatibility_command == "csr-candidate":
                    _print_candidate_root_help(name)
                elif compatibility_command == "ca-rollover":
                    _print_rollover_root_help(name)
                else:
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
