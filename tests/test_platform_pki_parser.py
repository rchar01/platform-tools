from __future__ import annotations

from types import MappingProxyType

import pytest

from src.platform_pki.parser import (
    ROUTES,
    ROUTE_SPECS,
    ParserError,
    leading_action,
    parse_route,
    render_route_help,
)

from .pki.migration_contract import (
    PKI_DUPLICATE_OPTION_CONTRACTS,
    PKI_PARSER_ROUTES,
)


MINIMAL_ARGUMENTS = {
    ("init",): (),
    ("inventory-install",): (),
    ("csr-trust-install",): (),
    ("csr-recover",): (),
    ("offline-csr", "approve"): (
        "api",
        "--operation",
        "issue",
        "--request-id",
        "0123456789abcdef0123456789abcdef",
        "--input-dir",
        "request",
        "--approval-key",
        "approval-key",
        "--output-dir",
        "approved",
        "--yes",
    ),
    ("offline-csr", "sign"): (
        "api",
        "--operation",
        "issue",
        "--request-id",
        "0123456789abcdef0123456789abcdef",
        "--input-dir",
        "approved",
        "--response-key",
        "response-key",
        "--yes",
    ),
    ("certificate-export", "publish"): (
        "api",
        "--request-id",
        "0123456789abcdef0123456789abcdef",
    ),
    ("certificate-export", "resolve"): (
        "api",
        "--request-id",
        "0123456789abcdef0123456789abcdef",
        "--manifest-sha256",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    ),
    ("csr-candidate", "verify"): (
        "api",
        "--request-id",
        "0123456789abcdef0123456789abcdef",
    ),
    ("csr-candidate", "finalize"): (
        "api",
        "--request-id",
        "0123456789abcdef0123456789abcdef",
        "--artifact-manifest-sha256",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "--evidence-file",
        "evidence",
        "--evidence-signature",
        "signature",
        "--yes",
    ),
    ("csr-candidate", "abandon"): (
        "api",
        "--request-id",
        "0123456789abcdef0123456789abcdef",
        "--artifact-manifest-sha256",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "--evidence-file",
        "evidence",
        "--evidence-signature",
        "signature",
        "--yes",
    ),
    ("root-create",): ("--name", "Root", "--org", "Org", "--country", "US"),
    ("intermediate-create",): (
        "--name",
        "Intermediate",
        "--org",
        "Org",
        "--country",
        "US",
    ),
    ("service-issue",): ("api",),
    ("service-renew",): ("api",),
    ("service-verify",): ("api",),
    ("service-recover",): ("--transaction", "service-0123456789abcdef0123456789abcdef"),
    ("list-expiry",): (),
    ("print-cert",): ("api",),
    ("export-ansible",): (),
    ("backup",): (),
    ("custody-report",): (),
    ("ca-passphrase-verify",): ("--root-pass-file", "root.pass"),
    ("ca-rollover", "migrate"): ("--backup-receipt", "receipt"),
    ("ca-rollover", "status"): (),
    ("ca-rollover", "prepare"): (
        "--type",
        "intermediate",
        "--backup-receipt",
        "receipt",
        "--intermediate-name",
        "Intermediate",
        "--org",
        "Org",
        "--country",
        "US",
        "--root-pass-file",
        "root.pass",
        "--intermediate-pass-file",
        "intermediate.pass",
    ),
    ("ca-rollover", "recover"): (
        "--transaction",
        "transaction",
        "--action",
        "resume",
        "--yes",
    ),
}


def test_production_routes_exactly_match_source_backed_parser_inventory() -> None:
    assert tuple(spec.route for spec in ROUTES) == tuple(
        contract.unified_route for contract in PKI_PARSER_ROUTES
    )
    assert len(ROUTES) == len(ROUTE_SPECS) == 29
    for spec, contract in zip(ROUTES, PKI_PARSER_ROUTES, strict=True):
        assert tuple(positional.name for positional in spec.positionals) == contract.positionals
        assert tuple(option.name for option in spec.options) == contract.long_flags
        assert (
            tuple(positional.name for positional in spec.positionals if positional.required)
            + tuple(option.name for option in spec.options if option.required)
        ) == contract.required_names
        assert tuple(
            (option.name, option.default)
            for option in spec.options
            if option.default is not None
        ) == contract.defaults
        assert tuple(
            (option.name, option.choices)
            for option in spec.options
            if option.choices
        ) == contract.allowed_values
        assert tuple(
            (option.name, option.conflicts)
            for option in spec.options
            if option.conflicts
        ) == contract.conflicts
        assert (
            tuple(positional.name for positional in spec.positionals if positional.repeatable)
            + tuple(option.name for option in spec.options if option.repeatable)
        ) == contract.repeatable_entries
        assert tuple(
            (option.name, option.validator)
            for option in spec.options
            if option.validator is not None
        ) == contract.validators


def test_duplicate_rejection_exactly_matches_source_backed_inventory() -> None:
    expected = {contract.route: contract.fields for contract in PKI_DUPLICATE_OPTION_CONTRACTS}
    actual = {
        spec.route: spec.reject_duplicates
        for spec in ROUTES
        if spec.reject_duplicates
    }
    assert actual == expected


@pytest.mark.parametrize("route", tuple(MINIMAL_ARGUMENTS), ids=lambda route: "-".join(route))
def test_every_route_accepts_its_minimal_state_free_parser_shape(
    route: tuple[str, ...],
) -> None:
    result = parse_route(route, MINIMAL_ARGUMENTS[route])
    assert result.spec.route == route
    assert isinstance(result.values, MappingProxyType)


@pytest.mark.parametrize(
    ("argument", "version", "expected"),
    (
        ("--help", True, "help"),
        ("--help=x", True, "help"),
        ("-hv", True, "help"),
        ("--version", True, "version"),
        ("--version=x", True, "version"),
        ("-v=x", True, "version"),
        ("-vh", True, "version"),
        ("--version", False, None),
        ("--help=", True, None),
        ("-hx", True, "help"),
        ("-h/", True, None),
        ("-h\N{LATIN SMALL LETTER E WITH ACUTE}", True, None),
        ("--help.name=x", True, None),
    ),
)
def test_leading_actions_match_bashly_normalization(
    argument: str, version: bool, expected: str | None
) -> None:
    assert leading_action(argument, version=version) == expected


def test_exact_long_options_equals_and_interspersed_positionals() -> None:
    result = parse_route(
        ("service-verify",),
        ("--namespace=/tmp/pki", "api", "--min-days=000030"),
    )
    assert result["service"] == "api"
    assert result["--namespace"] == "/tmp/pki"
    assert result["--min-days"] == "000030"
    for arguments in (("api", "--namesp=/tmp"), ("api", "--namespace="), ("api", "--")):
        with pytest.raises(ParserError, match="invalid option"):
            parse_route(("service-verify",), arguments)
    with pytest.raises(ParserError) as unknown_equals:
        parse_route(("service-verify",), ("api", "--namesp=/tmp"))
    assert unknown_equals.value.render() == "invalid option: --namesp\n"


@pytest.mark.parametrize(
    ("arguments", "diagnostic"),
    (
        (("api", "--help=x"), "invalid option: --help"),
        (("api", "-hfoo"), "invalid option: -h"),
        (("api", "--namespace="), "invalid option: --namespace="),
        (("api", "--bad.name=x"), "invalid option: --bad.name=x"),
        (("api", "-h/"), "invalid option: -h/"),
        (("api", "-h\N{LATIN SMALL LETTER E WITH ACUTE}"), "invalid option: -hé"),
    ),
)
def test_nonleading_diagnostics_use_bashly_normalized_tokens(
    arguments: tuple[str, ...], diagnostic: str
) -> None:
    with pytest.raises(ParserError) as caught:
        parse_route(("service-verify",), arguments)
    assert caught.value.render() == f"{diagnostic}\n"


def test_missing_unknown_and_extra_arguments_fail_without_defaults_hiding_them() -> None:
    with pytest.raises(ParserError, match="missing required argument: SERVICE"):
        parse_route(("service-verify",), ())
    with pytest.raises(ParserError, match="requires an argument"):
        parse_route(("service-verify",), ("api", "--min-days"))
    with pytest.raises(ParserError, match="invalid argument: extra"):
        parse_route(("service-verify",), ("api", "extra"))


def test_defaults_choices_empty_values_and_days_validation() -> None:
    assert parse_route(("certificate-export", "resolve"), MINIMAL_ARGUMENTS[("certificate-export", "resolve")])["--format"] == "path"
    arguments = (*MINIMAL_ARGUMENTS[("certificate-export", "resolve")], "--format", "")
    assert parse_route(("certificate-export", "resolve"), arguments)["--format"] == "path"
    with pytest.raises(ParserError, match="invalid value"):
        parse_route(("certificate-export", "resolve"), (*arguments[:-2], "--format", "yaml"))
    for value in ("0", "x", "365001"):
        with pytest.raises(ParserError, match="validation error"):
            parse_route(("service-verify",), ("api", "--min-days", value))


def test_command_specific_duplicate_and_repeatable_behavior() -> None:
    result = parse_route(
        ("service-verify",),
        ("api", "--min-days", "10", "--min-days", "20"),
    )
    assert result["--min-days"] == "20"
    with pytest.raises(ParserError, match="Option must not be repeated") as error:
        parse_route(
            ("inventory-install",),
            ("--namespace", "one", "--namespace=two"),
        )
    assert error.value.application
    backup = parse_route(
        ("backup",),
        ("--age-recipient", "one", "--age-recipient=two"),
    )
    assert backup["--age-recipient"] == ("one", "two")
    export = parse_route(("export-ansible",), ("api", "db", "api"))
    assert export["services"] == ("api", "db", "api")


def test_parser_validation_precedes_command_level_duplicate_guards() -> None:
    with pytest.raises(ParserError) as caught:
        parse_route(
            ("custody-report",),
            (
                "--namespace",
                "one",
                "--namespace",
                "two",
                "--format",
                "yaml",
            ),
        )
    assert not caught.value.application
    assert "Format must be text or json: yaml" in caught.value.message


def test_parser_diagnostics_replace_terminal_controls() -> None:
    for control in ("\x1b", "\u0085", "\u202e", "\u2028"):
        with pytest.raises(ParserError) as caught:
            parse_route(("service-verify",), ("api", f"--bad{control}text"))
        assert control not in caught.value.render()
        assert "--bad?text" in caught.value.render()


def test_conflicts_are_symmetric() -> None:
    for arguments in (
        ("--root-pass-file", "pass", "--allow-unencrypted-root-key"),
        ("--allow-unencrypted-root-key", "--root-pass-file", "pass"),
    ):
        with pytest.raises(ParserError, match="conflicting options"):
            parse_route(
                ("root-create",),
                ("--name", "Root", "--org", "Org", "--country", "US", *arguments),
            )


def test_host_local_relationships_are_checked_before_handler_dispatch() -> None:
    with pytest.raises(ParserError, match="host-local issuance requires --request-file"):
        parse_route(("service-issue",), ("api", "--csr-file", "request.csr"))
    complete = tuple(
        item
        for option in _host_local_options(include_current=False)
        for item in (option, f"{option[2:]}.value")
    )
    with pytest.raises(ParserError, match="--days is unavailable"):
        parse_route(("service-issue",), ("api", *complete, "--days", "30"))
    with pytest.raises(ParserError, match="host-local renewal requires --current-cert-file"):
        parse_route(("service-renew",), ("api", *complete))
    renewal = tuple(
        item
        for option in _host_local_options(include_current=True)
        for item in (option, f"{option[2:]}.value")
    )
    with pytest.raises(
        ParserError,
        match="--days is unavailable for host-local CSR signing; inventory is authoritative",
    ):
        parse_route(("service-renew",), ("api", *renewal, "--days", "30"))
    with pytest.raises(ParserError, match="--rotate-key conflicts with --csr-file"):
        parse_route(("service-renew",), ("api", *renewal, "--rotate-key"))

    offline = MINIMAL_ARGUMENTS[("offline-csr", "approve")]
    with pytest.raises(ParserError, match="renewal requires --current-cert-file"):
        parse_route(
            ("offline-csr", "approve"),
            tuple("renew" if value == "issue" else value for value in offline),
        )
    with pytest.raises(ParserError, match="available only for offline CSR renewal"):
        parse_route(
            ("offline-csr", "sign"),
            (*MINIMAL_ARGUMENTS[("offline-csr", "sign")], "--current-cert-file", "cert"),
        )


def _host_local_options(*, include_current: bool) -> tuple[str, ...]:
    options = (
        "--csr-file",
        "--request-file",
        "--request-signature",
        "--approval-file",
        "--approval-signature",
        "--response-key",
    )
    return (*options, "--current-cert-file") if include_current else options


def test_passphrase_and_rollover_argument_relationships() -> None:
    with pytest.raises(ParserError, match="At least one"):
        parse_route(("ca-passphrase-verify",), ())
    with pytest.raises(ParserError, match="expected 64-hex"):
        parse_route(
            ("ca-rollover", "migrate"),
            ("--backup-receipt", "receipt", "--yes"),
        )
    fingerprint = "a" * 64
    result = parse_route(
        ("ca-rollover", "migrate"),
        (
            "--backup-receipt",
            "receipt",
            "--yes",
            "--expected-root-sha256",
            fingerprint.upper(),
            "--expected-intermediate-sha256",
            fingerprint,
        ),
    )
    assert result["--expected-root-sha256"] == fingerprint.upper()


def test_rollover_prepare_type_relationships_and_tty_requirement() -> None:
    base = (
        "--backup-receipt",
        "receipt",
        "--intermediate-name",
        "Intermediate",
        "--org",
        "Org",
        "--country",
        "US",
    )
    with pytest.raises(ParserError, match="root-name is required"):
        parse_route(
            ("ca-rollover", "prepare"),
            ("--type", "root", *base, "--root-pass-file", "root", "--intermediate-pass-file", "intermediate"),
        )
    with pytest.raises(ParserError, match="forbidden"):
        parse_route(
            ("ca-rollover", "prepare"),
            ("--type", "intermediate", *base, "--root-name", "Root", "--root-pass-file", "root", "--intermediate-pass-file", "intermediate"),
        )
    with pytest.raises(ParserError, match="interactive TTY"):
        parse_route(("ca-rollover", "prepare"), ("--type", "intermediate", *base))
    assert parse_route(
        ("ca-rollover", "prepare"),
        ("--type", "intermediate", *base),
        interactive=True,
    ).spec.route == ("ca-rollover", "prepare")


def test_help_lists_every_option_for_unified_invocation() -> None:
    spec = ROUTE_SPECS[("certificate-export", "resolve")]
    unified = render_route_help(spec)
    assert unified.startswith(
        "Usage: platform-pki certificate-export resolve SERVICE [OPTIONS]\n"
    )
    for option in spec.options:
        assert option.name in unified
