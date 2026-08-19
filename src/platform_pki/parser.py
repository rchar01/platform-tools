"""Parser contracts for the unified PKI command surface."""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any


_HELP_FLAGS = frozenset(("-h", "--help"))
_VERSION_FLAGS = frozenset(("-v", "--version"))
_LONG_OPTION = re.compile(r"--[A-Za-z0-9_-]+", re.ASCII)
_SHORT_OPTION = re.compile(r"-[A-Za-z0-9]", re.ASCII)
_SHORT_CLUSTER = re.compile(r"-[A-Za-z0-9]{2,}", re.ASCII)
_BOOLEAN_OPTIONS = frozenset(
    (
        "--force",
        "--yes",
        "--allow-unencrypted-root-key",
        "--allow-unencrypted-intermediate-key",
        "--rotate-key",
        "--allow-plain-backup",
    )
)
_CSR_INPUT_OPTIONS = (
    "--csr-file",
    "--request-file",
    "--request-signature",
    "--approval-file",
    "--approval-signature",
    "--response-key",
    "--current-cert-file",
)
_OPTION_METAVARS = {
    "--namespace": "PATH",
    "--pki-dir": "PATH",
    "--private-repo": "PATH",
    "--transaction": "ID",
    "--response-key": "PATH",
    "--outcome-key": "PATH",
    "--approval-key": "PATH",
    "--input-dir": "PATH",
    "--output-dir": "PATH",
    "--operation": "OPERATION",
    "--request-id": "ID",
    "--manifest-sha256": "DIGEST",
    "--format": "FORMAT",
    "--artifact-manifest-sha256": "DIGEST",
    "--evidence-file": "PATH",
    "--evidence-signature": "PATH",
    "--name": "CN",
    "--org": "ORG",
    "--country": "COUNTRY",
    "--days": "DAYS",
    "--root-pass-file": "PATH",
    "--issuer-safety-days": "DAYS",
    "--intermediate-pass-file": "PATH",
    "--csr-file": "PATH",
    "--request-file": "PATH",
    "--request-signature": "PATH",
    "--approval-file": "PATH",
    "--approval-signature": "PATH",
    "--current-cert-file": "PATH",
    "--min-days": "DAYS",
    "--warn-days": "DAYS",
    "--critical-days": "DAYS",
    "--export-dir": "PATH",
    "--backup-dir": "PATH",
    "--age-recipient": "VALUE",
    "--backup-receipt": "PATH",
    "--expected-root-sha256": "DIGEST",
    "--expected-intermediate-sha256": "DIGEST",
    "--type": "TYPE",
    "--root-name": "CN",
    "--intermediate-name": "CN",
    "--root-days": "DAYS",
    "--intermediate-days": "DAYS",
    "--action": "ACTION",
    "--exchange-root": "PATH",
    "--stage": "STAGE",
    "--service": "SERVICE",
    "--target": "TARGET",
    "--package-version": "VERSION",
    "--source-dir": "PATH",
    "--destination-dir": "PATH",
    "--project-record": "PATH",
    "--token-type": "TYPE",
    "--token-file": "PATH",
    "--ca-file": "PATH",
    "--inventory-record": "PATH",
    "--trust-dir": "PATH",
    "--transport-host-key-sha256": "DIGEST",
    "--timeout": "SECONDS",
    "--processing-attempts": "COUNT",
    "--processing-interval": "SECONDS",
}


class ParserError(Exception):
    """A state-free parser diagnostic."""

    def __init__(self, message: str, *, application: bool = False) -> None:
        if (
            not isinstance(message, str)
            or not message
            or any(
                (
                    unicodedata.category(character)
                    in {"Cc", "Cf", "Cs", "Zl", "Zp"}
                )
                and character != "\n"
                for character in message
            )
        ):
            raise ValueError("parser diagnostic must be nonempty text")
        self.message = message
        self.application = application
        super().__init__(message)

    def render(self) -> str:
        prefix = "[ERROR] " if self.application else ""
        return f"{prefix}{self.message.rstrip(chr(10))}\n"


@dataclass(frozen=True, slots=True)
class PositionalSpec:
    name: str
    metavar: str
    required: bool = False
    repeatable: bool = False


@dataclass(frozen=True, slots=True)
class OptionSpec:
    name: str
    metavar: str | None = None
    required: bool = False
    default: str | None = None
    choices: tuple[str, ...] = ()
    validator: str | None = None
    repeatable: bool = False
    reject_duplicate: bool = False
    conflicts: tuple[str, ...] = ()

    @property
    def boolean(self) -> bool:
        return self.metavar is None


@dataclass(frozen=True, slots=True)
class RouteSpec:
    route: tuple[str, ...]
    positionals: tuple[PositionalSpec, ...]
    options: tuple[OptionSpec, ...]
    reject_duplicates: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ParseResult:
    spec: RouteSpec
    values: MappingProxyType[str, Any]
    provided: frozenset[str]

    def __getitem__(self, name: str) -> Any:
        return self.values[name]


def _option(
    name: str,
    *,
    required: bool = False,
    default: str | None = None,
    choices: tuple[str, ...] = (),
    validator: str | None = None,
    repeatable: bool = False,
    reject_duplicate: bool = False,
    conflicts: tuple[str, ...] = (),
) -> OptionSpec:
    return OptionSpec(
        name=name,
        metavar=None if name in _BOOLEAN_OPTIONS else _OPTION_METAVARS[name],
        required=required,
        default=default,
        choices=choices,
        validator=validator,
        repeatable=repeatable,
        reject_duplicate=reject_duplicate,
        conflicts=conflicts,
    )


def _options(
    names: tuple[str, ...],
    *,
    required: tuple[str, ...] = (),
    defaults: tuple[tuple[str, str], ...] = (),
    choices: tuple[tuple[str, tuple[str, ...]], ...] = (),
    validators: tuple[tuple[str, str], ...] = (),
    repeatable: tuple[str, ...] = (),
    reject_duplicates: tuple[str, ...] = (),
    conflicts: tuple[tuple[str, tuple[str, ...]], ...] = (),
) -> tuple[OptionSpec, ...]:
    default_map = dict(defaults)
    choice_map = dict(choices)
    validator_map = dict(validators)
    conflict_map = dict(conflicts)
    return tuple(
        _option(
            name,
            required=name in required,
            default=default_map.get(name),
            choices=choice_map.get(name, ()),
            validator=validator_map.get(name),
            repeatable=name in repeatable,
            reject_duplicate=name in reject_duplicates,
            conflicts=conflict_map.get(name, ()),
        )
        for name in names
    )


_NS = ("--namespace", "--pki-dir")
_NS_VALIDATORS = (("--namespace", "not_empty"), ("--pki-dir", "not_empty"))
_CERT_EXPORT_DUPLICATES = (
    "--request-id",
    "--manifest-sha256",
    "--format",
    "--namespace",
    "--pki-dir",
)
_CSR_OUTCOME_PUBLISH_DUPLICATES = (
    "--request-id",
    "--outcome-key",
    "--namespace",
    "--pki-dir",
)
_CSR_OUTCOME_RESOLVE_DUPLICATES = (
    "--request-id",
    "--manifest-sha256",
    "--format",
    "--namespace",
    "--pki-dir",
)
_CANDIDATE_DECISION_DUPLICATES = (
    "--request-id",
    "--artifact-manifest-sha256",
    "--evidence-file",
    "--evidence-signature",
    "--yes",
    "--namespace",
    "--pki-dir",
)


def _service(*, repeatable: bool = False) -> tuple[PositionalSpec, ...]:
    return (
        PositionalSpec(
            "services" if repeatable else "service",
            "SERVICES" if repeatable else "SERVICE",
            required=not repeatable,
            repeatable=repeatable,
        ),
    )


def _route(
    route: tuple[str, ...],
    option_names: tuple[str, ...],
    *,
    positionals: tuple[PositionalSpec, ...] = (),
    required: tuple[str, ...] = (),
    defaults: tuple[tuple[str, str], ...] = (),
    choices: tuple[tuple[str, tuple[str, ...]], ...] = (),
    validators: tuple[tuple[str, str], ...] = (),
    repeatable: tuple[str, ...] = (),
    reject_duplicates: tuple[str, ...] = (),
    conflicts: tuple[tuple[str, tuple[str, ...]], ...] = (),
) -> RouteSpec:
    return RouteSpec(
        route,
        positionals,
        _options(
            option_names,
            required=required,
            defaults=defaults,
            choices=choices,
            validators=validators,
            repeatable=repeatable,
            reject_duplicates=reject_duplicates,
            conflicts=conflicts,
        ),
        reject_duplicates,
    )


_SERVICE_OPTIONS = (
    *_NS,
    "--days",
    "--issuer-safety-days",
    "--intermediate-pass-file",
    "--rotate-key",
    *_CSR_INPUT_OPTIONS,
)
_SERVICE_VALIDATORS = (
    *_NS_VALIDATORS,
    ("--days", "days"),
    ("--issuer-safety-days", "days"),
    ("--intermediate-pass-file", "not_empty"),
    *((name, "not_empty") for name in _CSR_INPUT_OPTIONS),
)


ROUTES = (
    _route(("init",), (*_NS, "--force"), validators=_NS_VALIDATORS),
    _route(
        ("inventory-install",),
        ("--private-repo", *_NS),
        defaults=(("--private-repo", "../platform-private"),),
        validators=(("--private-repo", "not_empty"), *_NS_VALIDATORS),
        reject_duplicates=("--private-repo", *_NS),
    ),
    _route(
        ("csr-trust-install",),
        ("--private-repo", *_NS),
        defaults=(("--private-repo", "../platform-private"),),
        validators=(("--private-repo", "not_empty"), *_NS_VALIDATORS),
        reject_duplicates=("--private-repo", *_NS),
    ),
    _route(
        ("csr-recover",),
        ("--transaction", "--response-key", *_NS, "--yes"),
        validators=(("--transaction", "not_empty"), ("--response-key", "not_empty"), *_NS_VALIDATORS),
        reject_duplicates=("--transaction", "--response-key", *_NS, "--yes"),
    ),
    _route(
        ("offline-csr", "approve"),
        (
            "--operation",
            "--request-id",
            "--input-dir",
            "--approval-key",
            "--output-dir",
            "--current-cert-file",
            *_NS,
            "--yes",
        ),
        positionals=_service(),
        required=(
            "--operation",
            "--request-id",
            "--input-dir",
            "--approval-key",
            "--output-dir",
        ),
        choices=(("--operation", ("issue", "migrate", "renew")),),
        validators=(
            ("--request-id", "not_empty"),
            ("--input-dir", "not_empty"),
            ("--approval-key", "not_empty"),
            ("--output-dir", "not_empty"),
            ("--current-cert-file", "not_empty"),
            *_NS_VALIDATORS,
        ),
        reject_duplicates=(
            "--operation",
            "--request-id",
            "--input-dir",
            "--approval-key",
            "--output-dir",
            "--current-cert-file",
            *_NS,
            "--yes",
        ),
    ),
    _route(
        ("offline-csr", "sign"),
        (
            "--operation",
            "--request-id",
            "--input-dir",
            "--response-key",
            "--current-cert-file",
            "--intermediate-pass-file",
            "--issuer-safety-days",
            *_NS,
            "--yes",
        ),
        positionals=_service(),
        required=("--operation", "--request-id", "--input-dir", "--response-key"),
        defaults=(("--issuer-safety-days", "1"),),
        choices=(("--operation", ("issue", "migrate", "renew")),),
        validators=(
            ("--request-id", "not_empty"),
            ("--input-dir", "not_empty"),
            ("--response-key", "not_empty"),
            ("--current-cert-file", "not_empty"),
            ("--intermediate-pass-file", "not_empty"),
            ("--issuer-safety-days", "days"),
            *_NS_VALIDATORS,
        ),
        reject_duplicates=(
            "--operation",
            "--request-id",
            "--input-dir",
            "--response-key",
            "--current-cert-file",
            "--intermediate-pass-file",
            "--issuer-safety-days",
            *_NS,
            "--yes",
        ),
    ),
    _route(
        ("certificate-export", "publish"),
        ("--request-id", *_NS),
        positionals=_service(),
        required=("--request-id",),
        validators=(("--request-id", "not_empty"), *_NS_VALIDATORS),
        reject_duplicates=_CERT_EXPORT_DUPLICATES,
    ),
    _route(
        ("certificate-export", "resolve"),
        ("--request-id", "--manifest-sha256", "--format", *_NS),
        positionals=_service(),
        required=("--request-id", "--manifest-sha256"),
        defaults=(("--format", "path"),),
        choices=(("--format", ("path", "json")),),
        validators=(("--request-id", "not_empty"), ("--manifest-sha256", "not_empty"), *_NS_VALIDATORS),
        reject_duplicates=_CERT_EXPORT_DUPLICATES,
    ),
    _route(
        ("csr-outcome", "publish"),
        ("--request-id", "--outcome-key", *_NS),
        positionals=_service(),
        required=("--request-id", "--outcome-key"),
        validators=(
            ("--request-id", "not_empty"),
            ("--outcome-key", "not_empty"),
            *_NS_VALIDATORS,
        ),
        reject_duplicates=_CSR_OUTCOME_PUBLISH_DUPLICATES,
    ),
    _route(
        ("csr-outcome", "resolve"),
        ("--request-id", "--manifest-sha256", "--format", *_NS),
        positionals=_service(),
        required=("--request-id", "--manifest-sha256"),
        defaults=(("--format", "path"),),
        choices=(("--format", ("path", "json")),),
        validators=(
            ("--request-id", "not_empty"),
            ("--manifest-sha256", "not_empty"),
            *_NS_VALIDATORS,
        ),
        reject_duplicates=_CSR_OUTCOME_RESOLVE_DUPLICATES,
    ),
    _route(
        ("csr-candidate", "verify"),
        ("--request-id", "--format", *_NS),
        positionals=_service(),
        required=("--request-id",),
        defaults=(("--format", "text"),),
        choices=(("--format", ("text", "json")),),
        validators=(("--request-id", "not_empty"), *_NS_VALIDATORS),
        reject_duplicates=("--request-id", "--format", *_NS),
    ),
    *(
        _route(
            ("csr-candidate", action),
            (
                "--request-id",
                "--artifact-manifest-sha256",
                "--evidence-file",
                "--evidence-signature",
                "--yes",
                *_NS,
            ),
            positionals=_service(),
            required=(
                "--request-id",
                "--artifact-manifest-sha256",
                "--evidence-file",
                "--evidence-signature",
            ),
            validators=(
                ("--request-id", "not_empty"),
                ("--artifact-manifest-sha256", "not_empty"),
                ("--evidence-file", "not_empty"),
                ("--evidence-signature", "not_empty"),
                *_NS_VALIDATORS,
            ),
            reject_duplicates=_CANDIDATE_DECISION_DUPLICATES,
        )
        for action in ("finalize", "abandon")
    ),
    _route(
        ("root-create",),
        (*_NS, "--name", "--org", "--country", "--days", "--root-pass-file", "--allow-unencrypted-root-key", "--force"),
        required=("--name", "--org", "--country"),
        validators=(*_NS_VALIDATORS, ("--name", "not_empty"), ("--org", "not_empty"), ("--country", "not_empty"), ("--days", "days"), ("--root-pass-file", "not_empty")),
        conflicts=(("--root-pass-file", ("--allow-unencrypted-root-key",)), ("--allow-unencrypted-root-key", ("--root-pass-file",))),
    ),
    _route(
        ("intermediate-create",),
        (*_NS, "--name", "--org", "--country", "--days", "--issuer-safety-days", "--root-pass-file", "--intermediate-pass-file", "--allow-unencrypted-intermediate-key", "--force"),
        required=("--name", "--org", "--country"),
        defaults=(("--issuer-safety-days", "1"),),
        validators=(*_NS_VALIDATORS, ("--name", "not_empty"), ("--org", "not_empty"), ("--country", "not_empty"), ("--days", "days"), ("--issuer-safety-days", "days"), ("--root-pass-file", "not_empty"), ("--intermediate-pass-file", "not_empty")),
        conflicts=(("--intermediate-pass-file", ("--allow-unencrypted-intermediate-key",)), ("--allow-unencrypted-intermediate-key", ("--intermediate-pass-file",))),
    ),
    *(
        _route(
            (f"service-{action}",),
            _SERVICE_OPTIONS,
            positionals=_service(),
            defaults=(("--issuer-safety-days", "1"),),
            validators=_SERVICE_VALIDATORS,
            reject_duplicates=_CSR_INPUT_OPTIONS,
        )
        for action in ("issue", "renew")
    ),
    _route(
        ("service-verify",),
        (*_NS, "--min-days"),
        positionals=_service(),
        defaults=(("--min-days", "30"),),
        validators=(*_NS_VALIDATORS, ("--min-days", "days")),
    ),
    _route(
        ("service-recover",),
        ("--transaction", *_NS, "--yes"),
        required=("--transaction",),
        validators=(("--transaction", "not_empty"), *_NS_VALIDATORS),
        reject_duplicates=("--transaction", *_NS, "--yes"),
    ),
    _route(
        ("list-expiry",),
        (*_NS, "--warn-days", "--critical-days"),
        defaults=(("--warn-days", "90"), ("--critical-days", "30")),
        validators=(*_NS_VALIDATORS, ("--warn-days", "days"), ("--critical-days", "days")),
    ),
    _route(("print-cert",), _NS, positionals=_service(), validators=_NS_VALIDATORS),
    _route(
        ("export-ansible",),
        (*_NS, "--export-dir", "--force"),
        positionals=_service(repeatable=True),
        validators=(*_NS_VALIDATORS, ("--export-dir", "not_empty")),
    ),
    _route(
        ("backup",),
        (*_NS, "--backup-dir", "--age-recipient", "--allow-plain-backup"),
        validators=(*_NS_VALIDATORS, ("--backup-dir", "not_empty"), ("--age-recipient", "not_empty")),
        repeatable=("--age-recipient",),
    ),
    _route(
        ("custody-report",),
        (*_NS, "--format"),
        defaults=(("--format", "text"),),
        validators=(*_NS_VALIDATORS, ("--format", "format")),
        reject_duplicates=(*_NS, "--format"),
    ),
    _route(
        ("ca-passphrase-verify",),
        (*_NS, "--root-pass-file", "--intermediate-pass-file"),
        validators=(*_NS_VALIDATORS, ("--root-pass-file", "not_empty"), ("--intermediate-pass-file", "not_empty")),
        reject_duplicates=(*_NS, "--root-pass-file", "--intermediate-pass-file"),
    ),
    _route(
        ("ca-rollover", "migrate"),
        (*_NS, "--backup-receipt", "--private-repo", "--yes", "--expected-root-sha256", "--expected-intermediate-sha256"),
        required=("--backup-receipt",),
        defaults=(("--private-repo", "../platform-private"),),
        validators=(*_NS_VALIDATORS, ("--backup-receipt", "not_empty"), ("--private-repo", "not_empty"), ("--expected-root-sha256", "not_empty"), ("--expected-intermediate-sha256", "not_empty")),
        reject_duplicates=(*_NS, "--backup-receipt", "--private-repo", "--yes", "--expected-root-sha256", "--expected-intermediate-sha256"),
    ),
    _route(
        ("ca-rollover", "status"),
        (*_NS, "--format"),
        defaults=(("--format", "text"),),
        choices=(("--format", ("text", "json")),),
        validators=_NS_VALIDATORS,
        reject_duplicates=(*_NS, "--format"),
    ),
    _route(
        ("ca-rollover", "prepare"),
        (*_NS, "--type", "--backup-receipt", "--root-name", "--intermediate-name", "--org", "--country", "--root-days", "--intermediate-days", "--root-pass-file", "--intermediate-pass-file", "--issuer-safety-days", "--private-repo"),
        required=("--type", "--backup-receipt", "--intermediate-name", "--org", "--country"),
        defaults=(("--issuer-safety-days", "1"),),
        choices=(("--type", ("intermediate", "root")),),
        validators=(*_NS_VALIDATORS, ("--backup-receipt", "not_empty"), ("--root-name", "not_empty"), ("--intermediate-name", "not_empty"), ("--org", "not_empty"), ("--country", "not_empty"), ("--root-days", "not_empty"), ("--intermediate-days", "not_empty"), ("--root-pass-file", "not_empty"), ("--intermediate-pass-file", "not_empty"), ("--issuer-safety-days", "not_empty"), ("--private-repo", "not_empty")),
        reject_duplicates=(*_NS, "--type", "--backup-receipt", "--root-name", "--intermediate-name", "--org", "--country", "--root-days", "--intermediate-days", "--root-pass-file", "--intermediate-pass-file", "--issuer-safety-days", "--private-repo"),
    ),
    _route(
        ("ca-rollover", "recover"),
        (*_NS, "--transaction", "--action", "--yes"),
        required=("--transaction", "--action"),
        choices=(("--action", ("resume", "rollback")),),
        validators=(*_NS_VALIDATORS, ("--transaction", "not_empty")),
        reject_duplicates=(*_NS, "--transaction", "--action", "--yes"),
    ),
    _route(
        ("direct-exchange", "request-pull"),
        (),
        positionals=(
            PositionalSpec("endpoint", "ENDPOINT", required=True),
            PositionalSpec("request_id", "REQUEST_ID", required=True),
            PositionalSpec("output_dir", "OUTPUT_DIR", required=True),
        ),
    ),
    _route(
        ("direct-exchange", "evidence-pull"),
        (),
        positionals=(
            PositionalSpec("endpoint", "ENDPOINT", required=True),
            PositionalSpec("request_id", "REQUEST_ID", required=True),
            PositionalSpec("artifact_sha256", "ARTIFACT_SHA256", required=True),
            PositionalSpec("deployment_sha256", "DEPLOYMENT_SHA256", required=True),
            PositionalSpec("output_dir", "OUTPUT_DIR", required=True),
        ),
    ),
    _route(
        ("direct-exchange", "response-push"),
        (),
        positionals=(
            PositionalSpec("endpoint", "ENDPOINT", required=True),
            PositionalSpec("request_id", "REQUEST_ID", required=True),
            PositionalSpec("artifact_sha256", "ARTIFACT_SHA256", required=True),
            PositionalSpec("input_dir", "INPUT_DIR", required=True),
        ),
    ),
    _route(
        ("direct-exchange", "outcome-push"),
        (),
        positionals=(
            PositionalSpec("endpoint", "ENDPOINT", required=True),
            PositionalSpec("request_id", "REQUEST_ID", required=True),
            PositionalSpec("artifact_sha256", "ARTIFACT_SHA256", required=True),
            PositionalSpec("deployment_sha256", "DEPLOYMENT_SHA256", required=True),
            PositionalSpec("outcome_sha256", "OUTCOME_SHA256", required=True),
            PositionalSpec("input_dir", "INPUT_DIR", required=True),
        ),
    ),
    _route(
        ("gitlab-package", "publish"),
        (
            "--stage", "--service", "--target", "--request-id",
            "--package-version", "--source-dir", "--project-record",
            "--token-type", "--token-file", "--ca-file",
            "--inventory-record", "--trust-dir",
            "--transport-host-key-sha256", "--timeout",
            "--processing-attempts", "--processing-interval",
        ),
        required=(
            "--stage", "--service", "--target", "--request-id",
            "--package-version", "--source-dir", "--project-record",
            "--token-type", "--token-file", "--ca-file",
        ),
        defaults=(
            ("--timeout", "30"),
            ("--processing-attempts", "3"),
            ("--processing-interval", "2"),
        ),
        choices=(
            ("--stage", ("request", "approval", "response", "evidence", "outcome")),
            ("--token-type", ("job", "private", "deploy")),
        ),
        validators=tuple(
            (name, "not_empty")
            for name in (
                "--stage", "--service", "--target", "--request-id",
                "--package-version", "--source-dir", "--project-record",
                "--token-type", "--token-file", "--ca-file",
                "--inventory-record", "--trust-dir",
                "--transport-host-key-sha256", "--timeout",
                "--processing-attempts", "--processing-interval",
            )
        ),
        reject_duplicates=(
            "--stage", "--service", "--target", "--request-id",
            "--package-version", "--source-dir", "--project-record",
            "--token-type", "--token-file", "--ca-file",
            "--inventory-record", "--trust-dir",
            "--transport-host-key-sha256", "--timeout",
            "--processing-attempts", "--processing-interval",
        ),
    ),
    _route(
        ("gitlab-package", "download"),
        (
            "--stage", "--service", "--target", "--request-id",
            "--package-version", "--destination-dir", "--project-record",
            "--token-type", "--token-file", "--ca-file",
            "--inventory-record", "--trust-dir",
            "--transport-host-key-sha256", "--timeout",
            "--processing-attempts", "--processing-interval",
        ),
        required=(
            "--stage", "--service", "--target", "--request-id",
            "--package-version", "--destination-dir", "--project-record",
            "--token-type", "--token-file", "--ca-file",
        ),
        defaults=(
            ("--timeout", "30"),
            ("--processing-attempts", "3"),
            ("--processing-interval", "2"),
        ),
        choices=(
            ("--stage", ("request", "approval", "response", "evidence", "outcome")),
            ("--token-type", ("job", "private", "deploy")),
        ),
        validators=tuple(
            (name, "not_empty")
            for name in (
                "--stage", "--service", "--target", "--request-id",
                "--package-version", "--destination-dir", "--project-record",
                "--token-type", "--token-file", "--ca-file",
                "--inventory-record", "--trust-dir",
                "--transport-host-key-sha256", "--timeout",
                "--processing-attempts", "--processing-interval",
            )
        ),
        reject_duplicates=(
            "--stage", "--service", "--target", "--request-id",
            "--package-version", "--destination-dir", "--project-record",
            "--token-type", "--token-file", "--ca-file",
            "--inventory-record", "--trust-dir",
            "--transport-host-key-sha256", "--timeout",
            "--processing-attempts", "--processing-interval",
        ),
    ),
    _route(
        ("gitlab-package", "publish-request"),
        (
            "--exchange-root", "--service", "--target", "--request-id",
            "--inventory-record", "--transport-host-key-sha256",
            "--project-record", "--token-type", "--token-file", "--ca-file",
            "--timeout", "--processing-attempts", "--processing-interval",
        ),
        required=(
            "--exchange-root", "--service", "--target", "--request-id",
            "--inventory-record", "--transport-host-key-sha256",
            "--project-record", "--token-type", "--token-file", "--ca-file",
        ),
        defaults=(
            ("--timeout", "30"),
            ("--processing-attempts", "3"),
            ("--processing-interval", "2"),
        ),
        choices=(("--token-type", ("job", "private")),),
        validators=tuple(
            (name, "not_empty")
            for name in (
                "--exchange-root", "--service", "--target", "--request-id",
                "--inventory-record", "--transport-host-key-sha256",
                "--project-record", "--token-type", "--token-file", "--ca-file",
                "--timeout", "--processing-attempts", "--processing-interval",
            )
        ),
        reject_duplicates=(
            "--exchange-root", "--service", "--target", "--request-id",
            "--inventory-record", "--transport-host-key-sha256",
            "--project-record", "--token-type", "--token-file", "--ca-file",
            "--timeout", "--processing-attempts", "--processing-interval",
        ),
    ),
)

ROUTE_SPECS = MappingProxyType({spec.route: spec for spec in ROUTES})


def leading_action(argument: str, *, version: bool) -> str | None:
    """Return a leading help/version action after Bashly-style normalization."""

    allowed = _HELP_FLAGS | (_VERSION_FLAGS if version else frozenset())
    if argument in allowed:
        return "help" if argument in _HELP_FLAGS else "version"
    if "=" in argument:
        flag, value = argument.split("=", 1)
        if (
            value
            and flag in allowed
            and (_LONG_OPTION.fullmatch(flag) or _SHORT_OPTION.fullmatch(flag))
        ):
            return "help" if flag in _HELP_FLAGS else "version"
    if _SHORT_CLUSTER.fullmatch(argument):
        first = f"-{argument[1]}"
        if first in allowed:
            return "help" if first == "-h" else "version"
    return None


def _normalize_arguments(arguments: Sequence[str]) -> tuple[str, ...]:
    normalized: list[str] = []
    for argument in arguments:
        if "=" in argument:
            option, value = argument.split("=", 1)
            if value and (
                _LONG_OPTION.fullmatch(option) or _SHORT_OPTION.fullmatch(option)
            ):
                normalized.extend((option, value))
                continue
        if _SHORT_CLUSTER.fullmatch(argument):
            normalized.extend(f"-{character}" for character in argument[1:])
            continue
        normalized.append(argument)
    return tuple(normalized)


def _safe_text(value: str) -> str:
    return "".join(
        character
        if unicodedata.category(character) not in {"Cc", "Cf", "Cs", "Zl", "Zp"}
        else "?"
        for character in value
    )


def _validate_value(option: OptionSpec, value: str) -> None:
    if option.validator == "not_empty" and not value:
        raise ParserError(
            f"validation error in {option.name} {option.metavar}:\nvalue must not be empty"
        )
    if option.validator == "days":
        if not re.fullmatch(r"[0-9]+", value, re.ASCII):
            raise ParserError(
                f"validation error in {option.name} {option.metavar}:\nDays value must be numeric: {_safe_text(value)}"
            )
        normalized = value.lstrip("0") or "0"
        if len(normalized) > 6 or (len(normalized) == 6 and normalized > "365000"):
            raise ParserError(
                f"validation error in {option.name} {option.metavar}:\nDays value must be at most 365000: {_safe_text(value)}"
            )
        if normalized == "0":
            raise ParserError(
                f"validation error in {option.name} {option.metavar}:\nDays value must be at least 1: {_safe_text(value)}"
            )
    if option.validator == "format" and value not in ("text", "json"):
        raise ParserError(
            f"validation error in {option.name} VALUE:\n"
            f"Format must be text or json: {_safe_text(value)}"
        )
    if option.choices and value and value not in option.choices:
        choices = ", ".join(option.choices)
        raise ParserError(
            f"invalid value for {option.name} {option.metavar}: {_safe_text(value)}; allowed: {choices}"
        )


def _runtime_relationships(
    spec: RouteSpec,
    values: dict[str, Any],
    provided: set[str],
    explicit_empty: set[str],
    *,
    interactive: bool,
) -> None:
    route = spec.route
    if route in (("service-issue",), ("service-renew",)):
        host_local = any(option in provided for option in _CSR_INPUT_OPTIONS)
        if host_local:
            required = _CSR_INPUT_OPTIONS[:-1] if route == ("service-issue",) else _CSR_INPUT_OPTIONS
            operation = "issuance" if route == ("service-issue",) else "renewal"
            for option in required:
                if option not in provided:
                    raise ParserError(
                        f"Authenticated host-local {operation} requires {option}",
                        application=True,
                    )
            if "--days" in provided:
                raise ParserError(
                    "--days is unavailable for host-local CSR signing; inventory is authoritative",
                    application=True,
                )
            if "--rotate-key" in provided:
                raise ParserError(
                    "--rotate-key conflicts with --csr-file",
                    application=True,
                )
            if route == ("service-issue",) and "--current-cert-file" in provided:
                raise ParserError(
                    "--current-cert-file is available only for host-local renewal",
                    application=True,
                )
    elif route == ("ca-passphrase-verify",):
        if not {"--root-pass-file", "--intermediate-pass-file"} & provided:
            raise ParserError(
                "At least one of --root-pass-file or --intermediate-pass-file is required",
                application=True,
            )
    elif route in (("offline-csr", "approve"), ("offline-csr", "sign")):
        renewal = values["--operation"] == "renew"
        current = "--current-cert-file" in provided
        if renewal and not current:
            raise ParserError(
                "Offline CSR renewal requires --current-cert-file",
                application=True,
            )
        if not renewal and current:
            raise ParserError(
                "--current-cert-file is available only for offline CSR renewal",
                application=True,
            )
    elif route == ("ca-rollover", "migrate") and "--yes" in provided:
        for option in ("--expected-root-sha256", "--expected-intermediate-sha256"):
            value = values.get(option)
            if value is None or re.fullmatch(r"[0-9A-Fa-f]{64}", value) is None:
                raise ParserError(
                    "--yes requires both expected 64-hex SHA-256 fingerprints",
                    application=True,
                )
    elif route == ("ca-rollover", "prepare"):
        if "--type" in explicit_empty:
            raise ParserError("Candidate type must not be empty", application=True)
        if "--issuer-safety-days" in explicit_empty:
            raise ParserError(
                "Option must not be empty: --issuer-safety-days",
                application=True,
            )
        for option_name in ("--root-days", "--intermediate-days", "--issuer-safety-days"):
            if option_name in values:
                _validate_value(
                    OptionSpec(
                        option_name,
                        _OPTION_METAVARS[option_name],
                        validator="days",
                    ),
                    values[option_name],
                )
        if values["--type"] == "root" and "--root-name" not in provided:
            raise ParserError(
                "--root-name is required for root preparation", application=True
            )
        if values["--type"] == "intermediate":
            forbidden = ("--root-name", "--root-days", "--private-repo")
            if any(option in provided for option in forbidden):
                raise ParserError(
                    "--root-name, --root-days, and --private-repo are forbidden for intermediate preparation",
                    application=True,
                )
        if not interactive and not {
            "--root-pass-file",
            "--intermediate-pass-file",
        }.issubset(provided):
            raise ParserError(
                "Preparation without all required passphrase files requires an interactive TTY",
                application=True,
            )
    elif route == ("ca-rollover", "recover") and "--action" in explicit_empty:
        raise ParserError("Recovery action must not be empty", application=True)


def parse_route(
    route: tuple[str, ...],
    arguments: Sequence[str],
    *,
    interactive: bool = False,
) -> ParseResult:
    """Parse one frozen leaf without reading or mutating operational state."""

    try:
        spec = ROUTE_SPECS[route]
    except KeyError:
        raise ValueError("unknown parser route") from None
    if isinstance(arguments, (str, bytes)) or any(
        not isinstance(argument, str) for argument in arguments
    ):
        raise TypeError("arguments must be a sequence of strings")

    option_map = {option.name: option for option in spec.options}
    normalized_arguments = _normalize_arguments(arguments)
    values: dict[str, Any] = {}
    provided: set[str] = set()
    counts: dict[str, int] = {}
    explicit_empty: set[str] = set()
    positional_index = 0
    index = 0
    while index < len(normalized_arguments):
        token = normalized_arguments[index]
        if token.startswith("-") and token != "-":
            option = option_map.get(token)
            if option is None:
                raise ParserError(f"invalid option: {_safe_text(token)}")
            counts[token] = counts.get(token, 0) + 1
            provided.add(token)
            if option.boolean:
                values[token] = True
                index += 1
                continue
            if index + 1 >= len(normalized_arguments):
                raise ParserError(
                    f"{token} requires an argument: {token} {option.metavar}"
                )
            value = normalized_arguments[index + 1]
            index += 2
            if option.repeatable:
                values.setdefault(token, []).append(value)
            else:
                values[token] = value
            if not value:
                explicit_empty.add(token)
            continue

        if positional_index >= len(spec.positionals):
            raise ParserError(f"invalid argument: {_safe_text(token)}")
        positional = spec.positionals[positional_index]
        provided.add(positional.name)
        if positional.repeatable:
            values.setdefault(positional.name, []).append(token)
        else:
            values[positional.name] = token
            positional_index += 1
        index += 1

    for positional in spec.positionals:
        if positional.required and positional.name not in provided:
            usage = render_usage(spec)
            raise ParserError(
                f"missing required argument: {positional.metavar}\n{usage.rstrip()}"
            )
        if positional.repeatable:
            values[positional.name] = tuple(values.get(positional.name, ()))
    for option in spec.options:
        if option.required and option.name not in provided:
            raise ParserError(
                f"missing required flag: {option.name} {option.metavar}"
            )
        if option.default is not None and not values.get(option.name):
            values[option.name] = option.default

    for option in spec.options:
        if option.name in values:
            option_values = values[option.name]
            if option.repeatable:
                for value in option_values:
                    _validate_value(option, value)
                values[option.name] = tuple(option_values)
            elif not option.boolean:
                _validate_value(option, option_values)
        if option.name in provided:
            for conflict in option.conflicts:
                if conflict in provided:
                    raise ParserError(
                        f"conflicting options: {option.name} and {conflict}"
                    )

    for option in spec.options:
        if option.reject_duplicate and counts.get(option.name, 0) > 1:
            raise ParserError(
                f"Option must not be repeated: {option.name}", application=True
            )

    _runtime_relationships(
        spec,
        values,
        provided,
        explicit_empty,
        interactive=interactive,
    )
    return ParseResult(spec, MappingProxyType(values.copy()), frozenset(provided))


def render_usage(spec: RouteSpec) -> str:
    invocation = " ".join(("platform-pki", *spec.route))
    positionals = " ".join(
        f"[{positional.metavar}...]"
        if positional.repeatable
        else positional.metavar
        if positional.required
        else f"[{positional.metavar}]"
        for positional in spec.positionals
    )
    suffix = " ".join(part for part in (positionals, "[OPTIONS]") if part)
    return f"Usage: {invocation} {suffix}\n"


_ROUTE_FOOTERS: dict[tuple[str, ...], str] = {
    ("csr-outcome", "publish"): (
        "Authenticates one immutable finalized or abandoned signer outcome, "
        "requires the retained response signer key, and no-clobber-publishes "
        "an exact signed six-file package."
    ),
    ("csr-outcome", "resolve"): (
        "Requires the exact outcome-manifest digest and reauthenticates the "
        "package and retained source without claiming live target state."
    ),
    ("offline-csr", "approve"): (
        "Authenticates an exact three-file request snapshot, requires explicit "
        "review, and no-clobber-publishes one protected five-file approval "
        "directory without mutating CA, replay, candidate, or target state."
    ),
    ("offline-csr", "sign"): (
        "Authenticates an exact five-file approval snapshot and delegates every "
        "signing mutation to the host-local writer. Recovery remains exclusively "
        "through platform-pki csr-recover."
    ),
    ("ca-passphrase-verify",): (
        "Passphrases are supplied to OpenSSL through inherited file descriptors "
        "and are never placed in argv, the environment, or output. No receipt or "
        "persistent verification state is written."
    ),
    ("custody-report",): (
        "The report inspects managed PKI paths, file metadata, storage ancestry, "
        "age headers, and only the first PEM header line of validated private-key "
        "files. It never decrypts, parses, hashes, copies, or prints private-key "
        "content."
    ),
    ("direct-exchange", "request-pull"): (
        "Pull one exact request package over host-key-pinned restricted SSH."
    ),
    ("direct-exchange", "evidence-pull"): (
        "Pull one exact deployment evidence package over host-key-pinned restricted SSH."
    ),
    ("direct-exchange", "response-push"): (
        "Push one exact response package to the restricted target ingress."
    ),
    ("direct-exchange", "outcome-push"): (
        "Push one exact signer outcome package to the restricted target ingress."
    ),
    ("gitlab-package", "publish"): (
        "Validate and publish one exact host-local PKI package through GitLab."
    ),
    ("gitlab-package", "download"): (
        "Download, validate, and no-clobber-publish one exact GitLab PKI package."
    ),
    ("gitlab-package", "publish-request"): (
        "Compatibility publication for an existing validated request workspace."
    ),
}


def render_route_help(spec: RouteSpec) -> str:
    usage = render_usage(spec)
    lines = [usage.rstrip(), "", "Options:", "  -h, --help  Show this help"]
    for option in spec.options:
        label = option.name
        if option.metavar is not None:
            label += f" {option.metavar}"
        if option.repeatable:
            label += " ..."
        if option.required:
            label += "  (required)"
        elif option.default is not None:
            label += f"  (default: {option.default})"
        lines.append(f"  {label}")
    footer = _ROUTE_FOOTERS.get(spec.route)
    if footer is not None:
        lines.extend(("", footer))
    return "\n".join(lines) + "\n"
