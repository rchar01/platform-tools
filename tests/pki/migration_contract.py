from dataclasses import dataclass


LOCK_ORDER = ("lifecycle", "root", "intermediate", "inventory", "export")


@dataclass(frozen=True)
class CommandContract:
    compatibility_name: str
    unified_route: str
    nested_commands: tuple[str, ...]
    lock_profiles: tuple[tuple[str, ...], ...]
    test_targets: tuple[str, ...]


@dataclass(frozen=True)
class RecordContract:
    name: str
    schema: int | None
    ordering: str
    source: str
    fields: tuple[str, ...] | None = None


@dataclass(frozen=True)
class RecoveryContract:
    name: str
    operation: str
    schema: int
    compatibility_recovery: str
    checkpoint_source: str
    allowed_recovery_actions: tuple[str, ...]
    recovery_evidence: tuple[tuple[str, str, str], ...]


@dataclass(frozen=True)
class ParserRouteContract:
    compatibility_executable: str
    unified_route: tuple[str, ...]
    positionals: tuple[str, ...]
    long_flags: tuple[str, ...]
    required_names: tuple[str, ...]
    defaults: tuple[tuple[str, str], ...]
    allowed_values: tuple[tuple[str, tuple[str, ...]], ...]
    conflicts: tuple[tuple[str, tuple[str, ...]], ...]
    repeatable_entries: tuple[str, ...]
    validators: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class RuntimeOptionRelationship:
    route: tuple[str, ...]
    kind: str
    condition: str
    fields: tuple[str, ...]
    source: str
    source_fragment: str


@dataclass(frozen=True)
class DuplicateOptionContract:
    route: tuple[str, ...]
    fields: tuple[str, ...]
    source: str
    function: str = "pki_reject_repeated_options"


@dataclass(frozen=True)
class CheckpointCategory:
    name: str
    checkpoints: tuple[str, ...]


@dataclass(frozen=True)
class DynamicCheckpointFamily:
    template: str
    variable: str
    domain: tuple[str, ...]
    category: str
    source_declaration: str
    runtime_derived: bool = False


@dataclass(frozen=True)
class FaultHookContract:
    name: str
    operations: tuple[str, ...]
    schemas: tuple[int, ...]
    source: str
    hook: str
    fault_variables: tuple[str, ...]
    categories: tuple[CheckpointCategory, ...]
    dynamic_families: tuple[DynamicCheckpointFamily, ...]
    allowed_recovery_actions: tuple[str, ...]


@dataclass(frozen=True)
class StatusContract:
    code: int
    category: str
    meaning: str


@dataclass(frozen=True)
class OutputStatusContract:
    route: tuple[str, ...]
    scenario: str
    statuses: tuple[StatusContract, ...]
    stdout_kind: str
    stderr_kind: str
    stdout_final_newline: bool | None
    stderr_final_newline: bool | None
    evidence: tuple[tuple[str, str], ...]
    focused_tests: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class RuntimeDependencyContract:
    route: tuple[str, ...]
    program: str
    requirement: str
    condition: str
    capability: str
    source: str
    source_fragment: str


@dataclass(frozen=True)
class InstalledAssetContract:
    path: str
    mode: int
    consumers: tuple[tuple[str, ...], ...]
    lookup_order: tuple[str, ...]
    required_phase: str
    evidence: tuple[tuple[str, str], ...]
    focused_tests: tuple[tuple[str, str], ...]


def _locks(*profiles: tuple[str, ...]) -> tuple[tuple[str, ...], ...]:
    return profiles


def _route(
    compatibility_executable: str,
    unified_route: tuple[str, ...],
    *,
    positionals: tuple[str, ...] = (),
    long_flags: tuple[str, ...] = (),
    required_names: tuple[str, ...] = (),
    defaults: tuple[tuple[str, str], ...] = (),
    allowed_values: tuple[tuple[str, tuple[str, ...]], ...] = (),
    conflicts: tuple[tuple[str, tuple[str, ...]], ...] = (),
    repeatable_entries: tuple[str, ...] = (),
    validators: tuple[tuple[str, str], ...] = (),
) -> ParserRouteContract:
    return ParserRouteContract(
        compatibility_executable,
        unified_route,
        positionals,
        long_flags,
        required_names,
        defaults,
        allowed_values,
        conflicts,
        repeatable_entries,
        validators,
    )


def _phased(names: tuple[str, ...], phases: tuple[str, ...] = ("pending", "done")) -> tuple[str, ...]:
    return tuple(f"{name}-{phase}" for name in names for phase in phases)


PKI_COMMAND_CONTRACTS = (
    CommandContract(
        "platform-pki-init",
        "init",
        (),
        _locks(()),
        ("test-pki-init",),
    ),
    CommandContract(
        "platform-pki-inventory-install",
        "inventory-install",
        (),
        _locks(LOCK_ORDER[:4]),
        ("test-pki-inventory", "test-pki-inventory-install"),
    ),
    CommandContract(
        "platform-pki-csr-trust-install",
        "csr-trust-install",
        (),
        _locks(LOCK_ORDER[:4]),
        ("test-pki-csr-trust-install",),
    ),
    CommandContract(
        "platform-pki-csr-recover",
        "csr-recover",
        (),
        _locks(LOCK_ORDER[:4], LOCK_ORDER),
        ("test-pki-csr-signing", "test-pki-csr-candidate"),
    ),
    CommandContract(
        "platform-pki-certificate-export",
        "certificate-export",
        ("publish", "resolve"),
        _locks(LOCK_ORDER),
        ("test-pki-certificate-export",),
    ),
    CommandContract(
        "platform-pki-csr-candidate",
        "csr-candidate",
        ("verify", "finalize", "abandon"),
        _locks(LOCK_ORDER),
        ("test-pki-csr-candidate",),
    ),
    CommandContract(
        "platform-pki-root-create",
        "root-create",
        (),
        _locks(LOCK_ORDER[:2]),
        ("test-pki-root-create", "test-pki-pass-file", "test-pki-legacy-gating"),
    ),
    CommandContract(
        "platform-pki-intermediate-create",
        "intermediate-create",
        (),
        _locks(LOCK_ORDER[:3]),
        ("test-pki-intermediate-create", "test-pki-pass-file", "test-pki-legacy-gating"),
    ),
    CommandContract(
        "platform-pki-service-issue",
        "service-issue",
        (),
        _locks(LOCK_ORDER[:4]),
        ("test-pki-service-issue", "test-pki-csr-signing"),
    ),
    CommandContract(
        "platform-pki-service-renew",
        "service-renew",
        (),
        _locks(LOCK_ORDER[:4]),
        ("test-pki-service-renew", "test-pki-csr-signing"),
    ),
    CommandContract(
        "platform-pki-service-verify",
        "service-verify",
        (),
        _locks(LOCK_ORDER[:4]),
        ("test-pki-service-verify",),
    ),
    CommandContract(
        "platform-pki-list-expiry",
        "list-expiry",
        (),
        _locks(LOCK_ORDER[:4]),
        ("test-pki-list-expiry",),
    ),
    CommandContract(
        "platform-pki-print-cert",
        "print-cert",
        (),
        _locks(LOCK_ORDER[:4]),
        ("test-pki-print-cert",),
    ),
    CommandContract(
        "platform-pki-export-ansible",
        "export-ansible",
        (),
        _locks(LOCK_ORDER),
        ("test-pki-export",),
    ),
    CommandContract(
        "platform-pki-backup",
        "backup",
        (),
        _locks(LOCK_ORDER),
        ("test-pki-backup",),
    ),
    CommandContract(
        "platform-pki-custody-report",
        "custody-report",
        (),
        _locks(LOCK_ORDER),
        ("test-pki-custody-report",),
    ),
    CommandContract(
        "platform-pki-ca-passphrase-verify",
        "ca-passphrase-verify",
        (),
        _locks(LOCK_ORDER[:3]),
        ("test-pki-ca-passphrase-verify", "test-pki-pass-file"),
    ),
    CommandContract(
        "platform-pki-ca-rollover",
        "ca-rollover",
        ("migrate", "status", "prepare", "recover"),
        _locks(LOCK_ORDER),
        ("test-pki-ca-rollover", "test-pki-ca-rollover-parser"),
    ),
)


_NAMESPACE_FLAGS = ("--namespace", "--pki-dir")
_NAMESPACE_VALIDATORS = (("--namespace", "not_empty"), ("--pki-dir", "not_empty"))
_CSR_INPUT_FLAGS = (
    "--csr-file",
    "--request-file",
    "--request-signature",
    "--approval-file",
    "--approval-signature",
    "--response-key",
    "--current-cert-file",
)

PKI_PARSER_ROUTES = (
    _route("platform-pki-init", ("init",), long_flags=(*_NAMESPACE_FLAGS, "--force"), validators=_NAMESPACE_VALIDATORS),
    _route(
        "platform-pki-inventory-install", ("inventory-install",),
        long_flags=("--private-repo", *_NAMESPACE_FLAGS), defaults=(("--private-repo", "../platform-private"),),
        validators=(("--private-repo", "not_empty"), *_NAMESPACE_VALIDATORS),
    ),
    _route(
        "platform-pki-csr-trust-install", ("csr-trust-install",),
        long_flags=("--private-repo", *_NAMESPACE_FLAGS), defaults=(("--private-repo", "../platform-private"),),
        validators=(("--private-repo", "not_empty"), *_NAMESPACE_VALIDATORS),
    ),
    _route(
        "platform-pki-csr-recover", ("csr-recover",),
        long_flags=("--transaction", "--response-key", *_NAMESPACE_FLAGS, "--yes"),
        validators=(("--transaction", "not_empty"), ("--response-key", "not_empty"), *_NAMESPACE_VALIDATORS),
    ),
    _route(
        "platform-pki-certificate-export", ("certificate-export", "publish"),
        positionals=("service",), long_flags=("--request-id", *_NAMESPACE_FLAGS),
        required_names=("service", "--request-id"),
        validators=(("--request-id", "not_empty"), *_NAMESPACE_VALIDATORS),
    ),
    _route(
        "platform-pki-certificate-export", ("certificate-export", "resolve"),
        positionals=("service",),
        long_flags=("--request-id", "--manifest-sha256", "--format", *_NAMESPACE_FLAGS),
        required_names=("service", "--request-id", "--manifest-sha256"), defaults=(("--format", "path"),),
        allowed_values=(("--format", ("path", "json")),),
        validators=(("--request-id", "not_empty"), ("--manifest-sha256", "not_empty"), *_NAMESPACE_VALIDATORS),
    ),
    _route(
        "platform-pki-csr-candidate", ("csr-candidate", "verify"),
        positionals=("service",), long_flags=("--request-id", "--format", *_NAMESPACE_FLAGS),
        required_names=("service", "--request-id"), defaults=(("--format", "text"),),
        allowed_values=(("--format", ("text", "json")),),
        validators=(("--request-id", "not_empty"), *_NAMESPACE_VALIDATORS),
    ),
    _route(
        "platform-pki-csr-candidate", ("csr-candidate", "finalize"),
        positionals=("service",),
        long_flags=("--request-id", "--artifact-manifest-sha256", "--evidence-file", "--evidence-signature", "--yes", *_NAMESPACE_FLAGS),
        required_names=("service", "--request-id", "--artifact-manifest-sha256", "--evidence-file", "--evidence-signature"),
        validators=(("--request-id", "not_empty"), ("--artifact-manifest-sha256", "not_empty"), ("--evidence-file", "not_empty"), ("--evidence-signature", "not_empty"), *_NAMESPACE_VALIDATORS),
    ),
    _route(
        "platform-pki-csr-candidate", ("csr-candidate", "abandon"),
        positionals=("service",),
        long_flags=("--request-id", "--artifact-manifest-sha256", "--evidence-file", "--evidence-signature", "--yes", *_NAMESPACE_FLAGS),
        required_names=("service", "--request-id", "--artifact-manifest-sha256", "--evidence-file", "--evidence-signature"),
        validators=(("--request-id", "not_empty"), ("--artifact-manifest-sha256", "not_empty"), ("--evidence-file", "not_empty"), ("--evidence-signature", "not_empty"), *_NAMESPACE_VALIDATORS),
    ),
    _route(
        "platform-pki-root-create", ("root-create",),
        long_flags=(*_NAMESPACE_FLAGS, "--name", "--org", "--country", "--days", "--root-pass-file", "--allow-unencrypted-root-key", "--force"),
        required_names=("--name", "--org", "--country"),
        conflicts=(("--root-pass-file", ("--allow-unencrypted-root-key",)), ("--allow-unencrypted-root-key", ("--root-pass-file",))),
        validators=(*_NAMESPACE_VALIDATORS, ("--name", "not_empty"), ("--org", "not_empty"), ("--country", "not_empty"), ("--days", "days"), ("--root-pass-file", "not_empty")),
    ),
    _route(
        "platform-pki-intermediate-create", ("intermediate-create",),
        long_flags=(*_NAMESPACE_FLAGS, "--name", "--org", "--country", "--days", "--issuer-safety-days", "--root-pass-file", "--intermediate-pass-file", "--allow-unencrypted-intermediate-key", "--force"),
        required_names=("--name", "--org", "--country"), defaults=(("--issuer-safety-days", "1"),),
        conflicts=(("--intermediate-pass-file", ("--allow-unencrypted-intermediate-key",)), ("--allow-unencrypted-intermediate-key", ("--intermediate-pass-file",))),
        validators=(*_NAMESPACE_VALIDATORS, ("--name", "not_empty"), ("--org", "not_empty"), ("--country", "not_empty"), ("--days", "days"), ("--issuer-safety-days", "days"), ("--root-pass-file", "not_empty"), ("--intermediate-pass-file", "not_empty")),
    ),
    *(
        _route(
            f"platform-pki-service-{action}", (f"service-{action}",), positionals=("service",),
            long_flags=(*_NAMESPACE_FLAGS, "--days", "--issuer-safety-days", "--intermediate-pass-file", "--rotate-key", *_CSR_INPUT_FLAGS),
            required_names=("service",), defaults=(("--issuer-safety-days", "1"),),
            validators=(*_NAMESPACE_VALIDATORS, ("--days", "days"), ("--issuer-safety-days", "days"), ("--intermediate-pass-file", "not_empty"), *((field, "not_empty") for field in _CSR_INPUT_FLAGS)),
        )
        for action in ("issue", "renew")
    ),
    _route(
        "platform-pki-service-verify", ("service-verify",), positionals=("service",),
        long_flags=(*_NAMESPACE_FLAGS, "--min-days"), required_names=("service",), defaults=(("--min-days", "30"),),
        validators=(*_NAMESPACE_VALIDATORS, ("--min-days", "days")),
    ),
    _route(
        "platform-pki-list-expiry", ("list-expiry",),
        long_flags=(*_NAMESPACE_FLAGS, "--warn-days", "--critical-days"),
        defaults=(("--warn-days", "90"), ("--critical-days", "30")),
        validators=(*_NAMESPACE_VALIDATORS, ("--warn-days", "days"), ("--critical-days", "days")),
    ),
    _route("platform-pki-print-cert", ("print-cert",), positionals=("service",), long_flags=_NAMESPACE_FLAGS, required_names=("service",), validators=_NAMESPACE_VALIDATORS),
    _route(
        "platform-pki-export-ansible", ("export-ansible",), positionals=("services",),
        long_flags=(*_NAMESPACE_FLAGS, "--export-dir", "--force"), repeatable_entries=("services",),
        validators=(*_NAMESPACE_VALIDATORS, ("--export-dir", "not_empty")),
    ),
    _route(
        "platform-pki-backup", ("backup",),
        long_flags=(*_NAMESPACE_FLAGS, "--backup-dir", "--age-recipient", "--allow-plain-backup"),
        repeatable_entries=("--age-recipient",),
        validators=(*_NAMESPACE_VALIDATORS, ("--backup-dir", "not_empty"), ("--age-recipient", "not_empty")),
    ),
    _route(
        "platform-pki-custody-report", ("custody-report",), long_flags=(*_NAMESPACE_FLAGS, "--format"),
        defaults=(("--format", "text"),), validators=(*_NAMESPACE_VALIDATORS, ("--format", "format")),
    ),
    _route(
        "platform-pki-ca-passphrase-verify", ("ca-passphrase-verify",),
        long_flags=(*_NAMESPACE_FLAGS, "--root-pass-file", "--intermediate-pass-file"),
        validators=(*_NAMESPACE_VALIDATORS, ("--root-pass-file", "not_empty"), ("--intermediate-pass-file", "not_empty")),
    ),
    _route(
        "platform-pki-ca-rollover", ("ca-rollover", "migrate"),
        long_flags=(*_NAMESPACE_FLAGS, "--backup-receipt", "--private-repo", "--yes", "--expected-root-sha256", "--expected-intermediate-sha256"),
        required_names=("--backup-receipt",), defaults=(("--private-repo", "../platform-private"),),
        validators=(*_NAMESPACE_VALIDATORS, ("--backup-receipt", "not_empty"), ("--private-repo", "not_empty"), ("--expected-root-sha256", "not_empty"), ("--expected-intermediate-sha256", "not_empty")),
    ),
    _route(
        "platform-pki-ca-rollover", ("ca-rollover", "status"), long_flags=(*_NAMESPACE_FLAGS, "--format"),
        defaults=(("--format", "text"),), allowed_values=(("--format", ("text", "json")),), validators=_NAMESPACE_VALIDATORS,
    ),
    _route(
        "platform-pki-ca-rollover", ("ca-rollover", "prepare"),
        long_flags=(*_NAMESPACE_FLAGS, "--type", "--backup-receipt", "--root-name", "--intermediate-name", "--org", "--country", "--root-days", "--intermediate-days", "--root-pass-file", "--intermediate-pass-file", "--issuer-safety-days", "--private-repo"),
        required_names=("--type", "--backup-receipt", "--intermediate-name", "--org", "--country"),
        defaults=(("--issuer-safety-days", "1"),), allowed_values=(("--type", ("intermediate", "root")),),
        validators=(*_NAMESPACE_VALIDATORS, ("--backup-receipt", "not_empty"), ("--root-name", "not_empty"), ("--intermediate-name", "not_empty"), ("--org", "not_empty"), ("--country", "not_empty"), ("--root-days", "not_empty"), ("--intermediate-days", "not_empty"), ("--root-pass-file", "not_empty"), ("--intermediate-pass-file", "not_empty"), ("--issuer-safety-days", "not_empty"), ("--private-repo", "not_empty")),
    ),
    _route(
        "platform-pki-ca-rollover", ("ca-rollover", "recover"),
        long_flags=(*_NAMESPACE_FLAGS, "--transaction", "--action", "--yes"),
        required_names=("--transaction", "--action"), allowed_values=(("--action", ("resume", "rollback")),),
        validators=(*_NAMESPACE_VALIDATORS, ("--transaction", "not_empty")),
    ),
)


PKI_RUNTIME_OPTION_RELATIONSHIPS = (
    RuntimeOptionRelationship(
        ("service-issue",), "conditional-required", "any host-local CSR field is present",
        _CSR_INPUT_FLAGS[:-1], "bashly/platform-pki-service-issue/src/root_command.sh",
        "Authenticated host-local issuance requires $option",
    ),
    RuntimeOptionRelationship(
        ("service-issue",), "conditional-conflict", "host-local CSR mode is selected",
        ("--days", "--rotate-key", "--current-cert-file"), "bashly/platform-pki-service-issue/src/root_command.sh",
        "--current-cert-file is available only for host-local renewal",
    ),
    RuntimeOptionRelationship(
        ("service-renew",), "conditional-required", "any host-local CSR field is present",
        _CSR_INPUT_FLAGS, "bashly/platform-pki-service-renew/src/root_command.sh",
        "Authenticated host-local renewal requires $option",
    ),
    RuntimeOptionRelationship(
        ("service-renew",), "conditional-conflict", "host-local CSR mode is selected",
        ("--days", "--rotate-key"), "bashly/platform-pki-service-renew/src/root_command.sh",
        "--days is unavailable for host-local CSR signing",
    ),
    RuntimeOptionRelationship(
        ("ca-passphrase-verify",), "conditional-required", "at least one member must be present",
        ("--root-pass-file", "--intermediate-pass-file"), "bashly/platform-pki-ca-passphrase-verify/src/root_command.sh",
        "At least one of --root-pass-file or --intermediate-pass-file is required",
    ),
    RuntimeOptionRelationship(
        ("csr-recover",), "conditional-required", "no candidate finalization journal exists",
        ("--transaction",), "bashly/platform-pki-csr-recover/src/root_command.sh",
        "--transaction is required for CSR signing recovery",
    ),
    RuntimeOptionRelationship(
        ("csr-recover",), "conditional-conflict", "a candidate finalization journal exists",
        ("--response-key",), "bashly/platform-pki-csr-recover/src/root_command.sh",
        "--response-key is not accepted for candidate finalization recovery",
    ),
    RuntimeOptionRelationship(
        ("csr-recover",), "confirmation", "--yes is absent",
        ("--yes", "--transaction"), "bashly/platform-pki-csr-recover/src/root_command.sh",
        '[[ $confirmation == "recover $RECOVERY_DESCRIPTION" ]]',
    ),
    *(
        RuntimeOptionRelationship(
            ("csr-candidate", action), "confirmation", "--yes is absent",
            ("--yes", "--request-id"), "bashly/platform-pki-csr-candidate/src/initialize.sh",
            '[[ $confirmation == "$action $service $request_id" ]]',
        )
        for action in ("finalize", "abandon")
    ),
    RuntimeOptionRelationship(
        ("ca-rollover", "migrate"), "conditional-required", "--yes is present",
        ("--expected-root-sha256", "--expected-intermediate-sha256"), "bashly/platform-pki-ca-rollover/src/migrate_command.sh",
        "--yes requires both expected 64-hex SHA-256 fingerprints",
    ),
    RuntimeOptionRelationship(
        ("ca-rollover", "migrate"), "confirmation", "--yes is absent",
        ("--yes", "--expected-root-sha256", "--expected-intermediate-sha256"), "bashly/platform-pki-ca-rollover/src/migrate_command.sh",
        '[[ $confirmation == "migrate $ROOT_FP $INT_FP" ]]',
    ),
    RuntimeOptionRelationship(
        ("ca-rollover", "prepare"), "empty", "required enum is explicitly empty",
        ("--type",), "bashly/platform-pki-ca-rollover/src/prepare_command.sh", "Candidate type must not be empty",
    ),
    RuntimeOptionRelationship(
        ("ca-rollover", "prepare"), "empty", "defaulted option is explicitly empty",
        ("--issuer-safety-days",), "bashly/platform-pki-ca-rollover/src/prepare_command.sh",
        "pki_reject_explicit_empty_options --issuer-safety-days",
    ),
    RuntimeOptionRelationship(
        ("ca-rollover", "prepare"), "conditional-required", "--type=root",
        ("--root-name",), "bashly/platform-pki-ca-rollover/src/prepare_command.sh",
        "--root-name is required for root preparation",
    ),
    RuntimeOptionRelationship(
        ("ca-rollover", "prepare"), "conditional-conflict", "--type=intermediate",
        ("--root-name", "--root-days", "--private-repo"), "bashly/platform-pki-ca-rollover/src/prepare_command.sh",
        "--root-name, --root-days, and --private-repo are forbidden for intermediate preparation",
    ),
    RuntimeOptionRelationship(
        ("ca-rollover", "prepare"), "conditional-required", "either passphrase file is absent without an interactive TTY",
        ("--root-pass-file", "--intermediate-pass-file"), "bashly/platform-pki-ca-rollover/src/prepare_command.sh",
        "Preparation without all required passphrase files requires an interactive TTY",
    ),
    RuntimeOptionRelationship(
        ("ca-rollover", "recover"), "empty", "required enum is explicitly empty",
        ("--action",), "bashly/platform-pki-ca-rollover/src/recover_command.sh", "Recovery action must not be empty",
    ),
    RuntimeOptionRelationship(
        ("ca-rollover", "recover"), "confirmation", "--yes is absent",
        ("--yes", "--transaction", "--action"), "bashly/platform-pki-ca-rollover/src/recover_command.sh",
        '[[ $confirmation == "recover $TRANSACTION $ACTION" ]]',
    ),
)


_CERTIFICATE_EXPORT_DUPLICATES = ("--request-id", "--manifest-sha256", "--format", "--namespace", "--pki-dir")
_CANDIDATE_DECISION_DUPLICATES = ("--request-id", "--artifact-manifest-sha256", "--evidence-file", "--evidence-signature", "--namespace", "--pki-dir", "--yes")
PKI_DUPLICATE_OPTION_CONTRACTS = (
    DuplicateOptionContract(("inventory-install",), ("--private-repo", "--namespace", "--pki-dir"), "bashly/platform-pki-inventory-install/src/root_command.sh", "reject_repeated_options"),
    DuplicateOptionContract(("csr-trust-install",), ("--private-repo", "--namespace", "--pki-dir"), "bashly/platform-pki-csr-trust-install/src/root_command.sh"),
    DuplicateOptionContract(("csr-recover",), ("--transaction", "--response-key", "--namespace", "--pki-dir", "--yes"), "bashly/platform-pki-csr-recover/src/root_command.sh"),
    DuplicateOptionContract(("certificate-export", "publish"), _CERTIFICATE_EXPORT_DUPLICATES, "bashly/platform-pki-certificate-export/src/initialize.sh"),
    DuplicateOptionContract(("certificate-export", "resolve"), _CERTIFICATE_EXPORT_DUPLICATES, "bashly/platform-pki-certificate-export/src/initialize.sh"),
    DuplicateOptionContract(("csr-candidate", "verify"), ("--request-id", "--format", "--namespace", "--pki-dir"), "bashly/platform-pki-csr-candidate/src/verify_command.sh"),
    DuplicateOptionContract(("csr-candidate", "finalize"), _CANDIDATE_DECISION_DUPLICATES, "bashly/platform-pki-csr-candidate/src/finalize_command.sh"),
    DuplicateOptionContract(("csr-candidate", "abandon"), _CANDIDATE_DECISION_DUPLICATES, "bashly/platform-pki-csr-candidate/src/abandon_command.sh"),
    DuplicateOptionContract(("service-issue",), _CSR_INPUT_FLAGS, "bashly/platform-pki-service-issue/src/root_command.sh"),
    DuplicateOptionContract(("service-renew",), _CSR_INPUT_FLAGS, "bashly/platform-pki-service-renew/src/root_command.sh"),
    DuplicateOptionContract(("custody-report",), ("--namespace", "--pki-dir", "--format"), "bashly/platform-pki-custody-report/src/root_command.sh"),
    DuplicateOptionContract(("ca-passphrase-verify",), ("--namespace", "--pki-dir", "--root-pass-file", "--intermediate-pass-file"), "bashly/platform-pki-ca-passphrase-verify/src/root_command.sh"),
    DuplicateOptionContract(("ca-rollover", "migrate"), ("--namespace", "--pki-dir", "--backup-receipt", "--private-repo", "--yes", "--expected-root-sha256", "--expected-intermediate-sha256"), "bashly/platform-pki-ca-rollover/src/migrate_command.sh"),
    DuplicateOptionContract(("ca-rollover", "status"), ("--namespace", "--pki-dir", "--format"), "bashly/platform-pki-ca-rollover/src/status_command.sh"),
    DuplicateOptionContract(("ca-rollover", "prepare"), ("--namespace", "--pki-dir", "--type", "--backup-receipt", "--root-name", "--intermediate-name", "--org", "--country", "--root-days", "--intermediate-days", "--root-pass-file", "--intermediate-pass-file", "--issuer-safety-days", "--private-repo"), "bashly/platform-pki-ca-rollover/src/prepare_command.sh"),
    DuplicateOptionContract(("ca-rollover", "recover"), ("--namespace", "--pki-dir", "--transaction", "--action", "--yes"), "bashly/platform-pki-ca-rollover/src/recover_command.sh"),
)


PILOT_OUTPUT_STATUS_CONTRACTS = (
    OutputStatusContract(
        ("print-cert",),
        "certificate-details",
        (StatusContract(0, "success", "certificate details were rendered"),),
        "service-prefix-plus-openssl-owned-lines",
        "empty",
        True,
        None,
        (
            ("bashly/platform-pki-print-cert/src/root_command.sh", "printf 'Service: %s\\n' \"$SERVICE\""),
            ("bashly/platform-pki-print-cert/src/root_command.sh", "openssl x509 -in \"$CERT\" -noout"),
        ),
        (("tests/pki/test_print_cert.py", "test_prints_certificate_details_in_command_order"),),
    ),
    OutputStatusContract(
        ("print-cert",),
        "optional-extension-missing",
        (StatusContract(0, "success", "required details were rendered"),),
        "service-prefix-plus-partial-openssl-owned-lines",
        "openssl-owned-optional-extension-diagnostics",
        True,
        None,
        (("bashly/platform-pki-print-cert/src/root_command.sh", "openssl x509 -in \"$CERT\" -noout -ext keyUsage || true"),),
        (("tests/pki/test_print_cert.py", "test_missing_optional_extension_preserves_openssl_diagnostic"),),
    ),
    OutputStatusContract(
        ("list-expiry",),
        "expiry-report",
        (
            StatusContract(0, "success", "all certificates are outside warning thresholds"),
            StatusContract(1, "semantic", "at least one certificate is within the warning threshold"),
            StatusContract(2, "semantic", "at least one certificate is within the critical threshold"),
            StatusContract(3, "semantic", "at least one inventory certificate is missing"),
        ),
        "fixed-width-ordered-table",
        "empty",
        True,
        None,
        (
            ("bashly/platform-pki-list-expiry/src/root_command.sh", "printf '%-24s %-22s %-10s %s\\n' 'SERVICE' 'EXPIRES' 'DAYS_LEFT' 'STATUS'"),
            ("bashly/platform-pki-list-expiry/src/root_command.sh", "EXIT_CODE=3"),
            ("bashly/platform-pki-list-expiry/src/root_command.sh", "EXIT_CODE=2"),
            ("bashly/platform-pki-list-expiry/src/root_command.sh", "EXIT_CODE=1"),
        ),
        (
            ("tests/pki/test_list_expiry.py", "test_real_certificate_lifetime_classification"),
            ("tests/pki/test_list_expiry.py", "test_missing_certificate_status"),
            ("tests/pki/test_list_expiry.py", "test_missing_status_dominates_regardless_of_inventory_order"),
        ),
    ),
    OutputStatusContract(
        ("service-verify",),
        "verified",
        (StatusContract(0, "success", "all ordered certificate checks passed"),),
        "exact-ok-line",
        "empty",
        True,
        None,
        (("bashly/platform-pki-service-verify/src/root_command.sh", "pki_ok \"Verified service certificate: $SERVICE\""),),
        (("tests/pki/test_service_verify.py", "test_successful_verification_order"),),
    ),
    OutputStatusContract(
        ("service-verify",),
        "verification-failed",
        (StatusContract(1, "validation", "an ordered certificate check failed"),),
        "empty",
        "optional-openssl-diagnostics-then-application-error-line",
        None,
        True,
        (
            ("bashly/platform-pki-service-verify/src/root_command.sh", "pki_verify_service_certificate \"$SERVICE\" \"$MIN_DAYS\""),
            ("lib/platform-pki-common.sh", "openssl x509 -in \"$1\" -noout -ext basicConstraints"),
            ("lib/platform-pki-common.sh", "pki_die() { printf '[ERROR] %s\\n' \"$*\" >&2; exit 1; }"),
        ),
        (("tests/pki/test_service_verify.py", "test_application_verification_failure_stops_in_order"),),
    ),
    OutputStatusContract(
        ("service-verify",),
        "trust-verification-failed",
        (StatusContract(1, "child-failure", "OpenSSL rejected the certificate chain"),),
        "empty",
        "openssl-owned-diagnostics",
        None,
        None,
        (("lib/platform-pki-common.sh", "openssl verify -CAfile \"$root_cert\" -untrusted \"$int_cert\" \"$cert\" >/dev/null"),),
        (("tests/pki/test_service_verify.py", "test_openssl_trust_failure_preserves_child_stderr"),),
    ),
)


PILOT_RUNTIME_DEPENDENCY_CONTRACTS = (
    *(
        RuntimeDependencyContract(
            (route,), "openssl", "required", "operational execution",
            "OpenSSL certificate inspection and verification",
            f"bashly/platform-pki-{route}/src/root_command.sh", "pki_require_cmd openssl",
        )
        for route in ("print-cert", "list-expiry", "service-verify")
    ),
    *(
        RuntimeDependencyContract(
            (route,), "flock", "required", "first operation lock acquisition",
            "nonblocking advisory locks over persistent lock files",
            "lib/platform-pki-common.sh", "pki_require_cmd flock",
        )
        for route in ("print-cert", "list-expiry", "service-verify")
    ),
    RuntimeDependencyContract(
        ("list-expiry",), "date", "required", "certificate expiry conversion",
        "GNU date UTC parsing with -d", "lib/platform-pki-common.sh",
        "date -u -d \"$not_after\" '+%Y-%m-%dT%H:%M:%SZ'",
    ),
    RuntimeDependencyContract(
        ("service-verify",), "cmp", "required", "managed key/certificate comparison",
        "quiet byte comparison", "lib/platform-pki-common.sh", "cmp -s \"$tmpdir/cert.pub\" \"$tmpdir/key.pub\"",
    ),
    RuntimeDependencyContract(
        ("service-verify",), "grep", "required", "inventory and extension validation",
        "fixed-string exact and substring matching", "lib/platform-pki-common.sh",
        "grep -F 'TLS Web Server Authentication'",
    ),
)


PILOT_INSTALLED_ASSET_CONTRACTS = (
    InstalledAssetContract(
        "lib/platform-pki-common.sh",
        0o644,
        (("print-cert",), ("list-expiry",), ("service-verify",)),
        (
            "PLATFORM_TOOLS_LIB_DIR",
            "checkout-relative",
            "PLATFORM_TOOLS_SHARE_DIR-or-XDG-user-share",
        ),
        "operational-only",
        (
            ("Makefile", "LIBS := lib/platform-pki-common.sh"),
            ("Makefile", "chmod 644 \"$(SHARE_DIR)/lib/platform-pki-common.sh\""),
            *(
                (f"bashly/platform-pki-{route}/src/root_command.sh", "PLATFORM_TOOLS_SHARE_DIR")
                for route in ("print-cert", "list-expiry", "service-verify")
            ),
        ),
        (
            ("tests/pki/test_print_cert.py", "test_installed_share_directory_layout"),
            ("tests/pki/test_list_expiry.py", "test_installed_share_directory_layout"),
            ("tests/pki/test_service_verify.py", "test_installed_share_directory_layout"),
        ),
    ),
)


ROOT_DB_KEYS = (
    "index", "index_attr", "serial", "crlnumber", "index_old",
    "index_attr_old", "serial_old", "crlnumber_old", "newcert",
)
CSR_DB_KEYS = ("index", "index_attr", "serial", "index_old", "index_attr_old", "serial_old", "newcert")


def _fields(value: str) -> tuple[str, ...]:
    return tuple(value.split())


CSR_REQUEST_FIELDS = _fields("""
schema request_id nonce created_epoch expires_epoch operation service target
requester_principal inventory_sha256 csr_sha256 csr_spki_sha256
current_cert_sha256 profile response_principal
""")
CSR_APPROVAL_FIELDS = _fields("""
schema request_id nonce created_epoch expires_epoch approver_principal
request_sha256 csr_sha256 inventory_sha256 operation service target profile
""")
CSR_JOURNAL_FIELDS = _fields("""
schema operation transaction phase committed recovery_step request_id nonce
operation_kind service target requester_principal approver_principal
response_principal request_sha256 approval_sha256 inventory_sha256 csr_sha256
csr_spki_sha256 current_cert_sha256 created_epoch transaction_dir
transaction_identity response_trust_path response_trust_identity
response_trust_sha256 sensitive_key_path sensitive_key_identity
sensitive_key_removed certificate_path certificate_identity certificate_sha256
chain_path chain_identity chain_sha256 fullchain_path fullchain_identity
fullchain_sha256 response_manifest_path response_manifest_identity
response_manifest_sha256 response_signature_path response_signature_identity
response_signature_sha256 candidate_stage candidate_stage_identity
candidate_destination candidate_destination_identity response_stage
response_stage_identity response_destination response_destination_identity
replay_request_path replay_request_identity replay_request_sha256
replay_nonce_path replay_nonce_identity replay_nonce_sha256
""") + tuple(
    f"db_{key}_{suffix}"
    for key in CSR_DB_KEYS
    for suffix in (
        "path", "pre_identity", "source", "source_identity", "source_object",
        "post_identity", "backup", "backup_identity",
    )
)
CANDIDATE_RESPONSE_FIELDS = _fields("""
schema request_id nonce operation service target request_sha256 approval_sha256
inventory_sha256 csr_sha256 csr_spki_sha256 certificate_sha256
certificate_spki_sha256 chain_sha256 issuer_root issuer_intermediate serial
not_before_epoch not_after_epoch candidate_state response_principal created_epoch
""")
CANDIDATE_RECORD_FIELDS = _fields("""
schema request_id nonce operation service target state request_sha256
approval_sha256 inventory_sha256 csr_sha256 csr_spki_sha256 certificate_sha256
chain_sha256 issuer_root issuer_intermediate serial response_sha256
response_signature_sha256 created_epoch
""")
CANDIDATE_ARTIFACT_FIELDS = _fields("""
schema kind service request_id operation target source_kind
source_response_sha256 source_response_signature_sha256 certificate_sha256
certificate_spki_sha256 chain_sha256 fullchain_sha256 issuer_root
issuer_intermediate serial not_before_epoch not_after_epoch candidate_state
deployment_state response_principal created_epoch
""")
CANDIDATE_DEPLOYMENT_FIELDS = _fields("""
schema request_id nonce operation service target request_sha256 response_sha256
response_signature_sha256 candidate_sha256 artifact_request_id
artifact_manifest_sha256 certificate_sha256 certificate_spki_sha256
chain_sha256 fullchain_sha256 action result local_certificate_sha256
local_key_spki_sha256 local_key_certificate_match served_certificate_sha256
served_intermediate_sha256 validation_boundary_sha256 validation_result
activation_epoch validation_epoch rollback_state rollback_hold_until_epoch
deployment_principal created_epoch expires_epoch
""")
CANDIDATE_ACTIVE_FIELDS = _fields("""
schema service target request_id operation certificate_sha256
certificate_spki_sha256 response_sha256 artifact_manifest_sha256
deployment_sha256 decision_sha256 activation_epoch rollback_hold_until_epoch
updated_epoch
""")
CANDIDATE_DECISION_FIELDS = _fields("""
schema action state service target request_id operation request_sha256
response_sha256 response_signature_sha256 candidate_sha256
artifact_manifest_sha256 certificate_sha256 certificate_spki_sha256
chain_sha256 fullchain_sha256 deployment_sha256
deployment_signature_sha256 deployers_sha256 predecessor_kind
predecessor_request_id predecessor_certificate_sha256
predecessor_certificate_spki_sha256 predecessor_intermediate_sha256
predecessor_response_sha256 predecessor_artifact_manifest_sha256
predecessor_deployment_sha256 predecessor_decision_sha256
resulting_active_request_id created_epoch
""")
CANDIDATE_SOURCE_KEYS = _fields("""
candidate_candidate candidate_tls_crt candidate_ca_chain_crt
candidate_fullchain_crt candidate_response candidate_response_sig
response_tls_crt response_ca_chain_crt response_fullchain_crt
response_response response_response_sig artifact_artifact artifact_tls_crt
artifact_ca_chain_crt artifact_fullchain_crt artifact_response
artifact_response_sig
""")
CANDIDATE_JOURNAL_FIELDS = _fields("""
schema operation service request_id phase outcome_stage outcome_stage_identity
outcome_destination outcome_destination_identity active_stage
active_stage_identity active_destination active_pre_identity active_mode
active_destination_identity active_pre_sha256 candidate_dir candidate_dir_identity
response_dir response_dir_identity transaction_dir transaction_dir_identity
response_trust_path response_trust_identity response_trust_sha256
candidate_path candidate_identity candidate_sha256 artifact_dir
artifact_dir_identity artifact_path artifact_identity artifact_sha256
response_path response_identity response_sha256 response_signature_path
response_signature_identity response_signature_sha256 deployment_sha256
deployment_signature_sha256 deployers_sha256 decision_sha256 active_sha256
outcome_deployment_identity outcome_deployment_signature_identity
outcome_deployers_identity outcome_decision_identity
""") + tuple(
    f"source_{key}_{suffix}"
    for key in CANDIDATE_SOURCE_KEYS
    for suffix in ("identity", "sha256")
)

ACTIVE_ISSUER_FIELDS = ("root", "intermediate")
GENERATION_RESERVATION_TRANSACTION_FIELDS = (
    "generation", "kind", "status", "transaction",
)
GENERATION_RESERVATION_BOOTSTRAP_CONSUMED_FIELDS = (
    "generation", "kind", "status", "fingerprint_sha256", "transaction",
)
GENERATION_RESERVATION_MIGRATION_FIELDS = (
    "generation", "kind", "status", "fingerprint_sha256", "source_identity",
)
BACKUP_RECEIPT_FIELDS = _fields("""
schema layout session backup_path backup_device backup_inode backup_size
backup_mode backup_owner archive_sha256 created_at created_epoch
state_manifest_sha256 private_metadata_sha256
""")
ROOT_BOOTSTRAP_JOURNAL_FIELDS = _fields("""
schema operation transaction phase generation authority_dir authority_identity
stage_dir stage_identity transaction_dir transaction_identity reservation
reservation_identity reservation_reserved_identity reservation_consumed_identity
reservation_abandoned_identity bootstrap_identity recovery_action recovery_step
committed
""")
ROOT_BOOTSTRAP_RECOVERY_FIELDS = tuple(sorted(ROOT_BOOTSTRAP_JOURNAL_FIELDS))
INTERMEDIATE_BOOTSTRAP_PREFIX_FIELDS = _fields("""
schema operation transaction phase root_generation intermediate_generation
root_dir intermediate_dir intermediate_identity stage_dir stage_identity
root_stage root_stage_identity transaction_dir transaction_identity
bootstrap_fingerprint issued_serial reservation reservation_identity
reservation_reserved_identity reservation_consumed_identity
reservation_abandoned_identity active_identity bootstrap_identity
bootstrap_rollback_identity root_mutated recovery_action recovery_step
""")
INTERMEDIATE_BOOTSTRAP_DB_FIELDS = tuple(
    f"root_{key}_{suffix}"
    for key in ROOT_DB_KEYS
    for suffix in ("pre_identity", "post_identity", "backup_identity")
)
INTERMEDIATE_BOOTSTRAP_JOURNAL_FIELDS = (
    INTERMEDIATE_BOOTSTRAP_PREFIX_FIELDS
    + INTERMEDIATE_BOOTSTRAP_DB_FIELDS
    + ("committed",)
)
INTERMEDIATE_BOOTSTRAP_RECOVERY_FIELDS = tuple(
    sorted(INTERMEDIATE_BOOTSTRAP_JOURNAL_FIELDS)
)
LEGACY_MIGRATION_JOURNAL_FIELDS = _fields("""
schema operation transaction phase legacy_root legacy_intermediate new_root
new_intermediate root_source_identity intermediate_source_identity root_sha256
intermediate_sha256 transaction_dir transaction_identity provenance_stage
provenance_dir provenance_identity provenance_manifest
provenance_manifest_identity provenance_manifest_sha256 receipt_identity
services_sha256 services_identity backup_receipt private_repo backup_session
backup_session_original_identity backup_session_published_identity
root_reservation root_reservation_original_identity
root_reservation_reserved_identity root_reservation_consumed_identity
root_reservation_rollback_identity intermediate_reservation
intermediate_reservation_original_identity
intermediate_reservation_reserved_identity
intermediate_reservation_consumed_identity
intermediate_reservation_rollback_identity root_config_original_identity
root_config_published_identity root_config_rollback_identity
root_config_backup_identity intermediate_config_original_identity
intermediate_config_published_identity intermediate_config_rollback_identity
intermediate_config_backup_identity issuer_ledger issuer_ledger_identity
issuer_ledger_sha256 quarantine_ledger quarantine_ledger_identity
quarantine_ledger_sha256 active_manifest active_original_identity
active_published_identity committed
""")
LEGACY_MIGRATION_RECOVERY_FIELDS = tuple(sorted(LEGACY_MIGRATION_JOURNAL_FIELDS))
LEGACY_MIGRATION_CHECKPOINT_FIELDS = tuple(
    sorted((*LEGACY_MIGRATION_JOURNAL_FIELDS, "recovery_action", "recovery_step"))
)
ROLLOVER_PREPARE_BASE_FIELDS = _fields("""
schema operation transaction type phase committed recovery_action recovery_step
terminal_outcome active_root active_intermediate active_manifest active_identity
candidate_root candidate_intermediate candidate_root_dir
candidate_intermediate_dir candidate_root_identity
candidate_intermediate_identity candidate_root_key_identity
candidate_root_cert_identity candidate_root_cert_sha256
candidate_intermediate_key_identity candidate_intermediate_csr_identity
candidate_intermediate_cert_identity candidate_intermediate_cert_sha256
candidate_chain_identity candidate_chain_sha256 candidate_root_tree_manifest
candidate_root_tree_manifest_identity candidate_root_tree_manifest_sha256
candidate_intermediate_tree_manifest candidate_intermediate_tree_manifest_identity
candidate_intermediate_tree_manifest_sha256 root_stage_tree_manifest
root_stage_tree_manifest_identity root_stage_tree_manifest_sha256
stage_tree_manifest stage_tree_manifest_identity stage_tree_manifest_sha256
transaction_tree_manifest transaction_tree_manifest_identity
transaction_tree_manifest_sha256 transaction_tree_manifest_sequence
transaction_tree_manifest_pending transaction_tree_manifest_pending_destination
transaction_tree_manifest_pending_identity transaction_tree_manifest_pending_sha256
transaction_dir transaction_identity stage_dir stage_identity root_stage
root_stage_identity root_stage_private_identity root_stage_key_identity
intermediate_stage_identity intermediate_stage_private_identity long_stage
long_dir long_identity long_manifest_identity long_manifest_sha256
long_tree_manifest long_tree_manifest_identity long_tree_manifest_sha256
trust_snapshot_identity pointer pointer_identity backup_receipt receipt_identity
backup_session backup_session_original_identity backup_session_identity
root_reservation root_reservation_reserved_identity
root_reservation_consumed_identity root_reservation_abandoned_identity
intermediate_reservation intermediate_reservation_reserved_identity
intermediate_reservation_consumed_identity
intermediate_reservation_abandoned_identity root_fingerprint
intermediate_fingerprint root_expiry intermediate_expiry trust_bundle_sha256
trust_snapshot_sha256 trust_source trust_source_identity issued_serial root_mutated
""")
ROLLOVER_PREPARE_ROOT_DB_FIELDS = tuple(
    field
    for key in ROOT_DB_KEYS
    for field in (
        f"root_{key}_pre_identity",
        f"root_{key}_post_identity",
        f"root_{key}_backup_identity",
        f"root_{key}_rollback_identity",
        f"root_{key}_source_identity",
        f"signing_{key}_pre_identity",
        f"signing_{key}_partial_identity",
        f"signing_{key}_was_absent",
    )
)
ROLLOVER_PREPARE_PREPARTIAL_NAMES = _fields("""
trust_snapshot root_stage_key root_stage_cert root_stage_index
root_stage_index_backup root_stage_index_attr root_stage_index_attr_backup
root_stage_serial root_stage_serial_backup root_stage_crlnumber
root_stage_crlnumber_backup root_stage_index_old_backup
root_stage_index_attr_old_backup root_stage_serial_old_backup
root_stage_crlnumber_old_backup candidate_root_key candidate_root_cert
candidate_intermediate_key candidate_intermediate_csr
candidate_intermediate_cert candidate_chain
""")
ROLLOVER_PREPARE_PREPARTIAL_FIELDS = tuple(
    f"{name}_{suffix}"
    for name in ROLLOVER_PREPARE_PREPARTIAL_NAMES
    for suffix in ("pre_identity", "partial_identity")
)
ROLLOVER_PREPARE_JOURNAL_FIELDS = tuple(sorted(
    ROLLOVER_PREPARE_BASE_FIELDS
    + ROLLOVER_PREPARE_ROOT_DB_FIELDS
    + ROLLOVER_PREPARE_PREPARTIAL_FIELDS
))
ROLLOVER_PREPARED_MANIFEST_FIELDS = _fields("""
schema transaction type phase created_at old_root old_intermediate candidate_root
candidate_intermediate old_root_fingerprint old_intermediate_fingerprint
candidate_root_fingerprint candidate_intermediate_fingerprint
candidate_root_expiry candidate_intermediate_expiry trust_bundle_sha256
trust_snapshot_sha256 candidate_root_tree_sha256
candidate_intermediate_tree_sha256 backup_state_sha256
""")


PERSISTED_RECORD_CONTRACTS = (
    RecordContract("active and service issuer", None, "literal issuer pair", "lib/platform-pki-common.sh", ACTIVE_ISSUER_FIELDS),
    RecordContract(
        "generation reservation transaction-bound",
        None,
        "literal transaction reservation",
        "bashly/platform-pki-ca-rollover/src/prepare_command.sh",
        GENERATION_RESERVATION_TRANSACTION_FIELDS,
    ),
    RecordContract(
        "generation reservation bootstrap consumed",
        None,
        "literal bootstrap consumed reservation",
        "bashly/platform-pki-root-create/src/root_command.sh",
        GENERATION_RESERVATION_BOOTSTRAP_CONSUMED_FIELDS,
    ),
    RecordContract(
        "generation reservation legacy migration",
        None,
        "literal migration reservation",
        "bashly/platform-pki-ca-rollover/src/migrate_command.sh",
        GENERATION_RESERVATION_MIGRATION_FIELDS,
    ),
    RecordContract("backup receipt", 2, "literal backup receipt", "src/platform_pki/backup.py", BACKUP_RECEIPT_FIELDS),
    RecordContract("root bootstrap journal", 3, "literal root bootstrap journal", "bashly/platform-pki-root-create/src/root_command.sh", ROOT_BOOTSTRAP_JOURNAL_FIELDS),
    RecordContract("root bootstrap recovery journal", 3, "C-locale recovery journal", "bashly/platform-pki-ca-rollover/src/recover_command.sh", ROOT_BOOTSTRAP_RECOVERY_FIELDS),
    RecordContract(
        "intermediate bootstrap journal",
        3,
        "literal intermediate bootstrap journal",
        "bashly/platform-pki-intermediate-create/src/root_command.sh",
        INTERMEDIATE_BOOTSTRAP_JOURNAL_FIELDS,
    ),
    RecordContract(
        "intermediate bootstrap recovery journal",
        3,
        "C-locale recovery journal",
        "bashly/platform-pki-ca-rollover/src/recover_command.sh",
        INTERMEDIATE_BOOTSTRAP_RECOVERY_FIELDS,
    ),
    RecordContract("CSR request", 1, "PKI_CSR_REQUEST_FIELDS", "lib/platform-pki-csr-sign.sh", CSR_REQUEST_FIELDS),
    RecordContract("CSR approval", 1, "PKI_CSR_APPROVAL_FIELDS", "lib/platform-pki-csr-sign.sh", CSR_APPROVAL_FIELDS),
    RecordContract("CSR signing journal", 1, "PKI_CSR_JOURNAL_FIELDS", "lib/platform-pki-csr-sign.sh", CSR_JOURNAL_FIELDS),
    RecordContract("CSR response", 1, "PKI_CANDIDATE_RESPONSE_FIELDS", "lib/platform-pki-csr-candidate.sh", CANDIDATE_RESPONSE_FIELDS),
    RecordContract("CSR candidate", 1, "PKI_CANDIDATE_RECORD_FIELDS", "lib/platform-pki-csr-candidate.sh", CANDIDATE_RECORD_FIELDS),
    RecordContract(
        "certificate export manifest",
        1,
        "PKI_CERTIFICATE_EXPORT_ARTIFACT_FIELDS",
        "bashly/platform-pki-certificate-export/src/initialize.sh",
        CANDIDATE_ARTIFACT_FIELDS,
    ),
    RecordContract("deployment evidence", 1, "PKI_CANDIDATE_DEPLOYMENT_FIELDS", "lib/platform-pki-csr-candidate.sh", CANDIDATE_DEPLOYMENT_FIELDS),
    RecordContract("active candidate", 1, "PKI_CANDIDATE_ACTIVE_FIELDS", "lib/platform-pki-csr-candidate.sh", CANDIDATE_ACTIVE_FIELDS),
    RecordContract("candidate outcome", 1, "PKI_CANDIDATE_DECISION_FIELDS", "lib/platform-pki-csr-candidate.sh", CANDIDATE_DECISION_FIELDS),
    RecordContract(
        "candidate finalization journal",
        1,
        "PKI_CANDIDATE_JOURNAL_FIELDS",
        "lib/platform-pki-csr-candidate.sh",
        CANDIDATE_JOURNAL_FIELDS,
    ),
    RecordContract("legacy migration journal", 2, "literal migration journal", "bashly/platform-pki-ca-rollover/src/migrate_command.sh", LEGACY_MIGRATION_JOURNAL_FIELDS),
    RecordContract("legacy migration recovery journal", 2, "C-locale recovery journal", "bashly/platform-pki-ca-rollover/src/recover_command.sh", LEGACY_MIGRATION_RECOVERY_FIELDS),
    RecordContract("legacy migration checkpoint journal", 2, "C-locale recovery checkpoint", "bashly/platform-pki-ca-rollover/src/recover_command.sh", LEGACY_MIGRATION_CHECKPOINT_FIELDS),
    RecordContract("rollover preparation journal", 5, "C-locale preparation journal", "bashly/platform-pki-ca-rollover/src/prepare_command.sh", ROLLOVER_PREPARE_JOURNAL_FIELDS),
    RecordContract("rollover prepared-state manifest", 1, "literal prepared-state manifest", "bashly/platform-pki-ca-rollover/src/prepare_command.sh", ROLLOVER_PREPARED_MANIFEST_FIELDS),
)


_CA_RECOVERY = "bashly/platform-pki-ca-rollover/src/recover_command.sh"
_CSR_RECOVERY = "bashly/platform-pki-csr-recover/src/root_command.sh"

RECOVERY_CONTRACTS = (
    RecoveryContract(
        "root bootstrap",
        "root-bootstrap",
        3,
        "platform-pki ca-rollover recover",
        "bashly/platform-pki-root-create/src/root_command.sh",
        ("rollback",),
        (
            ("route", _CA_RECOVERY, "${PKI_RECORD[operation]:-} == root-bootstrap"),
            ("rollback", _CA_RECOVERY, "Root bootstrap recovery supports only rollback"),
        ),
    ),
    RecoveryContract(
        "intermediate bootstrap",
        "intermediate-bootstrap",
        3,
        "platform-pki ca-rollover recover",
        "bashly/platform-pki-intermediate-create/src/root_command.sh",
        ("rollback", "resume"),
        (
            ("route", _CA_RECOVERY, "${PKI_RECORD[operation]:-} == intermediate-bootstrap"),
            ("resume", _CA_RECOVERY, "Intermediate bootstrap resume is limited to sensitive-stage cleanup"),
            ("rollback", _CA_RECOVERY, "Intermediate bootstrap recovery action is invalid"),
        ),
    ),
    RecoveryContract(
        "CSR signing",
        "csr-sign",
        1,
        "platform-pki csr-recover",
        "lib/platform-pki-csr-sign.sh",
        ("rollback-pre-commit", "resume-post-commit"),
        (
            ("route", _CSR_RECOVERY, "pki_csr_recover"),
            ("rollback-pre-commit", "lib/platform-pki-csr-sign.sh", "pki_csr_rollback_uncommitted_ca"),
            ("resume-post-commit", "lib/platform-pki-csr-sign.sh", "pki_csr_resume_committed"),
        ),
    ),
    RecoveryContract(
        "candidate finalization",
        "csr-finalize",
        1,
        "platform-pki csr-recover",
        "lib/platform-pki-csr-candidate.sh",
        ("resume",),
        (
            ("route", _CSR_RECOVERY, "pki_candidate_recover"),
            ("resume", "lib/platform-pki-csr-candidate.sh", "pki_candidate_resume_finalization"),
        ),
    ),
    RecoveryContract(
        "legacy migration",
        "legacy-migrate",
        2,
        "platform-pki ca-rollover recover",
        "bashly/platform-pki-ca-rollover/src/migrate_command.sh",
        ("rollback", "resume"),
        (
            ("route", _CA_RECOVERY, "${PKI_RECORD[operation]} == legacy-migrate"),
            ("rollback", _CA_RECOVERY, "if [[ $ACTION == rollback ]]; then"),
            ("resume", _CA_RECOVERY, "Resume each mutation only from its exact original identity"),
        ),
    ),
    RecoveryContract(
        "rollover preparation",
        "rollover-prepare",
        5,
        "platform-pki ca-rollover recover",
        "bashly/platform-pki-ca-rollover/src/prepare_command.sh",
        ("rollback", "resume"),
        (
            ("route", _CA_RECOVERY, "${PKI_RECORD[operation]:-} == rollover-prepare"),
            ("rollback", _CA_RECOVERY, "finish_recovered_preparation rolled-back"),
            ("resume", _CA_RECOVERY, "finish_recovered_preparation resumed"),
        ),
    ),
)


MIGRATION_QUARANTINE_NAMES = ("pki.env", "openssl-root.cnf.tpl", "openssl-intermediate.cnf.tpl", "openssl-service.cnf.tpl")

_PREPARE_DIRECT = (
    "transaction-manifest-staged", "transaction-manifest-published", "transaction-manifest-superseded",
    "after-journal", "after-transaction", "after-reservations", "after-staged", "after-root-candidate",
    "after-intermediate-candidate", "after-root-db", "after-consumed", "cleanup-root-stage-removed",
    "after-state", "after-pointer", "long-stage-created", "intermediate-signing-db-ready",
    "intermediate-signing-child-failed",
)
_PREPARE_PAIRED = (
    "transaction-dir", "backup-session", "reserve-root", "reserve-intermediate", "stage-dir",
    "sensitive-root-stage", "sensitive-root-private", "sensitive-intermediate-stage",
    "sensitive-intermediate-private", "candidate-root-directory", "candidate-root-private",
    "candidate-intermediate-directory", "candidate-intermediate-private", "intermediate-stage-config",
    "candidate-root-config", "evidence-stage", "publish-root", "publish-intermediate", "consume-root",
    "consume-intermediate", "cleanup-root-stage", "publish-state", "publish-pointer",
)
_PREPARE_COPY_LITERAL = ("trust-snapshot", "copied-root-key", "copied-root-cert")
_PREPARE_DESTINATION = ("root-key", "root-certificate", "intermediate-key", "intermediate-csr", "intermediate-signing", "chain")
_PREPARE_SINGLE_STATE = (
    "long-stage-pending", "long-stage-done", "sensitive-stage-pending", "sensitive-stage-done",
    "candidate-root-stage-pending", "candidate-root-stage-done", "root-key-done", "root-certificate-done",
    "intermediate-key-done", "intermediate-csr-done", "intermediate-signing-done", "chain-done",
)
_PREPARE_PRE_COMMIT = (
    *_PREPARE_DIRECT,
    *_phased(_PREPARE_PAIRED),
    *_PREPARE_SINGLE_STATE,
    *(_phased(_PREPARE_COPY_LITERAL, ("pending", "done", "child-failed"))),
    *(_phased(_PREPARE_DESTINATION, ("pending", "child-failed"))),
)
_TERMINAL_CHECKPOINTS = ("terminal-transaction-pending", "terminal-transaction-done", "terminal-journal-pending", "terminal-journal-done")

FAULT_HOOK_CONTRACTS = (
    FaultHookContract(
        "root bootstrap writer", ("root-bootstrap",), (3,), "bashly/platform-pki-root-create/src/root_command.sh", "root_fault",
        ("PLATFORM_PKI_ROOT_CRASH_AT", "PLATFORM_PKI_ROOT_SIGNAL_AT", "PLATFORM_PKI_ROOT_FAIL_AT"),
        (CheckpointCategory("pre-commit", ("after-journal", "after-reservation", "after-authority", "after-reservation-consumed", "after-bootstrap")),),
        (), ("rollback",),
    ),
    FaultHookContract(
        "intermediate bootstrap writer", ("intermediate-bootstrap",), (3,), "bashly/platform-pki-intermediate-create/src/root_command.sh", "intermediate_fault",
        ("PLATFORM_PKI_INTERMEDIATE_CRASH_AT", "PLATFORM_PKI_INTERMEDIATE_SIGNAL_AT", "PLATFORM_PKI_INTERMEDIATE_FAIL_AT"),
        (CheckpointCategory("pre-commit", (
            "after-journal", "after-reservation", "after-intermediate", "root-newcert-pending", "root-newcert-done",
            "after-root-db", "after-reservation-consumed", "after-active", "after-bootstrap", "cleanup-pending",
            "cleanup-removed", "cleanup-done",
        )),),
        (
            DynamicCheckpointFamily("root-{key}-pending", "key", ROOT_DB_KEYS[:-1], "pre-commit", "ROOT_DB_KEYS"),
            DynamicCheckpointFamily("root-{key}-done", "key", ROOT_DB_KEYS[:-1], "pre-commit", "ROOT_DB_KEYS"),
        ),
        ("rollback", "resume"),
    ),
    FaultHookContract(
        "CSR signing writer", ("csr-sign",), (1,), "lib/platform-pki-csr-sign.sh", "pki_csr_fault",
        ("PLATFORM_PKI_CSR_CRASH_AT", "PLATFORM_PKI_CSR_FAIL_AT"),
        (
            CheckpointCategory("pre-commit", ("after-journal", "replay-reserved", "transaction-staged", "signing-ready", "signing-complete", "sensitive-key-removed")),
            CheckpointCategory("post-commit", ("ca-committed", "response-signed", "candidate-published", "response-published", "before-journal-cleanup")),
        ),
        tuple(
            DynamicCheckpointFamily(template, "key", CSR_DB_KEYS, "pre-commit", "PKI_CSR_DB_KEYS")
            for template in ("after-ca-{key}-publish", "ca-{key}-published")
        ),
        ("rollback-pre-commit", "resume-post-commit"),
    ),
    FaultHookContract(
        "candidate finalization writer", ("csr-finalize",), (1,), "lib/platform-pki-csr-candidate.sh", "pki_candidate_fault",
        ("PLATFORM_PKI_CANDIDATE_CRASH_AT", "PLATFORM_PKI_CANDIDATE_FAIL_AT"),
        (CheckpointCategory("resume-only", ("journal-written", "outcome-published", "active-published")),),
        (), ("resume",),
    ),
    FaultHookContract(
        "legacy migration writer", ("legacy-migrate",), (2,), "bashly/platform-pki-ca-rollover/src/migrate_command.sh", "fault",
        ("PLATFORM_PKI_MIGRATE_CRASH_AT", "PLATFORM_PKI_MIGRATE_FAIL_AT"),
        (CheckpointCategory("pre-commit", ("after-journal", "after-reservations", "after-root-rename", "after-intermediate-rename", "after-configs", "after-issuers", "after-quarantine", "after-active")),),
        (), ("rollback", "resume"),
    ),
    FaultHookContract(
        "rollover preparation writer", ("rollover-prepare",), (5,), "bashly/platform-pki-ca-rollover/src/prepare_command.sh", "prepare_fault",
        ("PLATFORM_PKI_PREPARE_CRASH_AT", "PLATFORM_PKI_PREPARE_SIGNAL_AT", "PLATFORM_PKI_PREPARE_FAIL_AT"),
        (CheckpointCategory("pre-commit", _PREPARE_PRE_COMMIT), CheckpointCategory("post-commit", _TERMINAL_CHECKPOINTS)),
        (
            *(DynamicCheckpointFamily(f"copied-root-{{key}}-{phase}", "key", ROOT_DB_KEYS[:4], "pre-commit", "for spec in 'index.txt:index'", False) for phase in ("pending", "done", "child-failed")),
            *(DynamicCheckpointFamily(f"backup-root-{{key}}-{phase}", "key", ROOT_DB_KEYS[:-1], "pre-commit", "for spec in 'index.txt.old:index_old'", False) for phase in ("pending", "done", "child-failed")),
            DynamicCheckpointFamily("publish-root-db-{key}-pending", "key", ROOT_DB_KEYS, "pre-commit", "ROOT_DB_KEYS"),
            DynamicCheckpointFamily("publish-root-db-{key}-done", "key", ROOT_DB_KEYS, "pre-commit", "ROOT_DB_KEYS"),
        ),
        ("rollback", "resume"),
    ),
    FaultHookContract(
        "rollover recovery", ("root-bootstrap", "intermediate-bootstrap", "legacy-migrate", "rollover-prepare"), (2, 3, 5),
        "bashly/platform-pki-ca-rollover/src/recover_command.sh", "recover_fault", ("PLATFORM_PKI_RECOVER_CRASH_AT",),
        (CheckpointCategory("recovery", (
            *_TERMINAL_CHECKPOINTS,
            *_phased(("rollback-reservation-intermediate", "rollback-reservation-root", "rollback-backup-session", "rollback-pointer", "rollback-intermediate", "rollback-root", "rollback-state", "rollback-stage")),
            *_phased(("resume-backup-session", "resume-reserve-root", "resume-reserve-intermediate", "resume-publish-root", "resume-publish-intermediate", "resume-consume-root", "resume-consume-intermediate", "resume-cleanup-root-stage", "resume-publish-state", "resume-publish-pointer")),
            "cleanup-pending", "cleanup-done",
            *_phased(("rollback-bootstrap", "rollback-active", "rollback-authority", "rollback-reservation")),
            *_phased(("rollback-intermediate-rename", "rollback-root-rename", "rollback-provenance", "resume-backup-session", "resume-root-rename", "resume-intermediate-rename", "resume-active", "resume-provenance")),
        )),),
        (
            *(DynamicCheckpointFamily(f"rollback-root-{{key}}-{phase}", "key", ROOT_DB_KEYS, "recovery", "db_keys=(index", False) for phase in ("pending", "done")),
            *(DynamicCheckpointFamily(f"rollback-root-db-{{key}}-{phase}", "key", ROOT_DB_KEYS, "recovery", "ROOT_DB_KEYS=(index", False) for phase in ("pending", "done")),
            *(DynamicCheckpointFamily(f"resume-root-db-{{key}}-{phase}", "key", ROOT_DB_KEYS, "recovery", "ROOT_DB_KEYS=(index", False) for phase in ("pending", "done")),
            *(DynamicCheckpointFamily(f"rollback-config-{{label}}-{phase}", "label", ("root", "intermediate"), "recovery", "ROOT_LOCATION|root", False) for phase in ("pending", "done")),
            *(DynamicCheckpointFamily(f"resume-config-{{label}}-{phase}", "label", ("root", "intermediate"), "recovery", "NEW_ROOT/openssl.cnf|root", False) for phase in ("pending", "done")),
            *(DynamicCheckpointFamily(f"rollback-reservation-{{kind}}-{phase}", "kind", ("root", "intermediate"), "recovery", "ROOT_RESERVATION|root", False) for phase in ("pending", "done")),
            *(DynamicCheckpointFamily(f"resume-reservation-{{kind}}-{phase}", "kind", ("root", "intermediate"), "recovery", "ROOT_RESERVATION|root", False) for phase in ("pending", "done")),
            *(DynamicCheckpointFamily(f"resume-consume-{{kind}}-{phase}", "kind", ("root", "intermediate"), "recovery", "root-consumed.publish", False) for phase in ("pending", "done")),
            *(DynamicCheckpointFamily(f"rollback-quarantine-{{basename}}-{phase}", "basename", MIGRATION_QUARANTINE_NAMES, "recovery", "pki\\.env|openssl-root", False) for phase in ("pending", "done")),
            *(DynamicCheckpointFamily(f"resume-quarantine-{{basename}}-{phase}", "basename", MIGRATION_QUARANTINE_NAMES, "recovery", "pki\\.env|openssl-root", False) for phase in ("pending", "done")),
            *(DynamicCheckpointFamily(f"rollback-issuer-{{service}}-{phase}", "service", (), "recovery", "ISSUER_LEDGER", True) for phase in ("pending", "done")),
            *(DynamicCheckpointFamily(f"resume-issuer-{{service}}-{phase}", "service", (), "recovery", "ISSUER_LEDGER", True) for phase in ("pending", "done")),
        ),
        ("rollback", "resume"),
    ),
)
