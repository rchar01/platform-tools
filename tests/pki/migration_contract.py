from dataclasses import dataclass

from src.platform_pki.ca_rollover_recovery import (
    INTERMEDIATE_BOOTSTRAP_DB_FIELDS,
    INTERMEDIATE_BOOTSTRAP_PREFIX_FIELDS,
    INTERMEDIATE_BOOTSTRAP_RECOVERY_FIELDS,
    INTERMEDIATE_BOOTSTRAP_WRITER_FIELDS as INTERMEDIATE_BOOTSTRAP_JOURNAL_FIELDS,
    LEGACY_MIGRATION_CHECKPOINT_FIELDS,
    LEGACY_MIGRATION_RECOVERY_FIELDS,
    LEGACY_MIGRATION_WRITER_FIELDS as LEGACY_MIGRATION_JOURNAL_FIELDS,
    ROLLOVER_PREPARE_BASE_FIELDS,
    ROLLOVER_PREPARE_DECLARED_FIELDS as ROLLOVER_PREPARE_JOURNAL_FIELDS,
    ROLLOVER_PREPARE_PREPARTIAL_FIELDS,
    ROLLOVER_PREPARE_PREPARTIAL_NAMES,
    ROLLOVER_PREPARE_ROOT_DB_FIELDS,
    ROLLOVER_PREPARE_RUNTIME_IDENTITY_FIELDS,
    ROOT_BOOTSTRAP_RECOVERY_FIELDS,
    ROOT_BOOTSTRAP_WRITER_FIELDS as ROOT_BOOTSTRAP_JOURNAL_FIELDS,
    ROOT_DB_KEYS,
)
from src.platform_pki.csr_recovery import (
    CANDIDATE_FINALIZATION_JOURNAL_FIELDS as CANDIDATE_JOURNAL_FIELDS,
    CANDIDATE_SOURCE_KEYS,
    CSR_DB_KEYS,
    CSR_SIGNING_JOURNAL_FIELDS as CSR_JOURNAL_FIELDS,
)
from src.platform_pki.csr_recover import CSR_FINALIZATION_RECOVERY_CHECKPOINTS
from src.platform_pki.csr_history import (
    CSR_ACTIVE_FIELDS as CANDIDATE_ACTIVE_FIELDS,
    CSR_ARTIFACT_FIELDS as CANDIDATE_ARTIFACT_FIELDS,
    CSR_DECISION_FIELDS as CANDIDATE_DECISION_FIELDS,
    CSR_DEPLOYMENT_FIELDS as CANDIDATE_DEPLOYMENT_FIELDS,
)
from src.platform_pki.csr_protocol import (
    CSR_APPROVAL_FIELDS,
    CSR_CANDIDATE_FIELDS as CANDIDATE_RECORD_FIELDS,
    CSR_REPLAY_NONCE_FIELDS,
    CSR_REPLAY_REQUEST_FIELDS,
    CSR_REQUEST_FIELDS,
    CSR_RESPONSE_FIELDS as CANDIDATE_RESPONSE_FIELDS,
    CSR_TERMINAL_FIELDS,
)
from src.platform_pki.root_create import ROOT_FAULT_CHECKPOINTS, ROOT_FAULT_VARIABLES
from src.platform_pki.service_transaction import (
    SERVICE_RETAINED_ROLLBACK_FIELDS,
    SERVICE_RETAINED_TERMINAL_FIELDS,
    SERVICE_RETAINED_TRANSACTION_FIELDS,
    SERVICE_TRANSACTION_FIELDS,
)


LOCK_ORDER = ("lifecycle", "root", "intermediate", "inventory", "export")


@dataclass(frozen=True)
class CommandContract:
    compatibility_name: str | None
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
    compatibility_executable: str | None
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


@dataclass(frozen=True)
class HistoricalOracleAssetContract:
    path: str
    mode: int
    consumers: tuple[tuple[str, ...], ...]
    evidence: tuple[tuple[str, str], ...]
    focused_tests: tuple[tuple[str, str], ...]


def _locks(*profiles: tuple[str, ...]) -> tuple[tuple[str, ...], ...]:
    return profiles


def _route(
    compatibility_executable: str | None,
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
        None,
        "offline-csr",
        ("approve", "sign"),
        _locks(LOCK_ORDER[:4]),
        ("test-pki-offline-csr",),
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
        None,
        "service-recover",
        (),
        _locks(LOCK_ORDER[:4]),
        ("test-pki-service-recover",),
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
        None, ("offline-csr", "approve"), positionals=("service",),
        long_flags=("--operation", "--request-id", "--input-dir", "--approval-key", "--output-dir", "--current-cert-file", *_NAMESPACE_FLAGS, "--yes"),
        required_names=("service", "--operation", "--request-id", "--input-dir", "--approval-key", "--output-dir"),
        allowed_values=(("--operation", ("issue", "migrate", "renew")),),
        validators=(("--request-id", "not_empty"), ("--input-dir", "not_empty"), ("--approval-key", "not_empty"), ("--output-dir", "not_empty"), ("--current-cert-file", "not_empty"), *_NAMESPACE_VALIDATORS),
    ),
    _route(
        None, ("offline-csr", "sign"), positionals=("service",),
        long_flags=("--operation", "--request-id", "--input-dir", "--response-key", "--current-cert-file", "--intermediate-pass-file", "--issuer-safety-days", *_NAMESPACE_FLAGS, "--yes"),
        required_names=("service", "--operation", "--request-id", "--input-dir", "--response-key"),
        defaults=(("--issuer-safety-days", "1"),),
        allowed_values=(("--operation", ("issue", "migrate", "renew")),),
        validators=(("--request-id", "not_empty"), ("--input-dir", "not_empty"), ("--response-key", "not_empty"), ("--current-cert-file", "not_empty"), ("--intermediate-pass-file", "not_empty"), ("--issuer-safety-days", "days"), *_NAMESPACE_VALIDATORS),
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
        None, ("service-recover",),
        long_flags=("--transaction", *_NAMESPACE_FLAGS, "--yes"),
        required_names=("--transaction",),
        validators=(("--transaction", "not_empty"), *_NAMESPACE_VALIDATORS),
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
        _CSR_INPUT_FLAGS, "src/platform_pki/parser.py",
        "Authenticated host-local {operation} requires {option}",
    ),
    RuntimeOptionRelationship(
        ("service-renew",), "conditional-conflict", "host-local CSR mode is selected",
        ("--days", "--rotate-key"), "src/platform_pki/parser.py",
        "--days is unavailable for host-local CSR signing; inventory is authoritative",
    ),
    RuntimeOptionRelationship(
        ("ca-passphrase-verify",), "conditional-required", "at least one member must be present",
        ("--root-pass-file", "--intermediate-pass-file"), "bashly/platform-pki-ca-passphrase-verify/src/root_command.sh",
        "At least one of --root-pass-file or --intermediate-pass-file is required",
    ),
    RuntimeOptionRelationship(
        ("csr-recover",), "conditional-required", "no candidate finalization journal exists",
        ("--transaction",), "src/platform_pki/csr_recover.py",
        "--transaction is required for CSR signing recovery",
    ),
    RuntimeOptionRelationship(
        ("csr-recover",), "conditional-conflict", "a candidate finalization journal exists",
        ("--response-key",), "src/platform_pki/csr_recover.py",
        "--response-key is not accepted for candidate finalization recovery",
    ),
    RuntimeOptionRelationship(
        ("csr-recover",), "confirmation", "--yes is absent",
        ("--yes", "--transaction"), "src/platform_pki/csr_recover.py",
        'confirmation != f"recover {description}"',
    ),
    RuntimeOptionRelationship(
        ("service-recover",), "confirmation", "--yes is absent",
        ("--yes", "--transaction"), "src/platform_pki/service_recover.py",
        'sys.stdin.readline().rstrip("\\n") != f"recover {transaction}"',
    ),
    RuntimeOptionRelationship(
        ("offline-csr", "approve"), "conditional-required", "--operation=renew",
        ("--operation", "--current-cert-file"), "src/platform_pki/parser.py",
        "Offline CSR renewal requires --current-cert-file",
    ),
    RuntimeOptionRelationship(
        ("offline-csr", "sign"), "confirmation", "--yes is absent",
        ("--operation", "--request-id", "--yes"), "src/platform_pki/offline_csr.py",
        'f"sign {operation} {service} {request_id}"',
    ),
    *(
        RuntimeOptionRelationship(
            ("csr-candidate", action), "confirmation", "--yes is absent",
            ("--yes", "--request-id"), "src/platform_pki/csr_candidate.py",
            'sys.stdin.readline().rstrip("\\n") != f"{action} {service_name} {request_id}"',
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
_CANDIDATE_DECISION_DUPLICATES = ("--request-id", "--artifact-manifest-sha256", "--evidence-file", "--evidence-signature", "--yes", "--namespace", "--pki-dir")
PKI_DUPLICATE_OPTION_CONTRACTS = (
    DuplicateOptionContract(("inventory-install",), ("--private-repo", "--namespace", "--pki-dir"), "bashly/platform-pki-inventory-install/src/root_command.sh", "reject_repeated_options"),
    DuplicateOptionContract(("csr-trust-install",), ("--private-repo", "--namespace", "--pki-dir"), "bashly/platform-pki-csr-trust-install/src/root_command.sh"),
    DuplicateOptionContract(("csr-recover",), ("--transaction", "--response-key", "--namespace", "--pki-dir", "--yes"), "bashly/platform-pki-csr-recover/src/root_command.sh"),
    DuplicateOptionContract(("csr-recover",), ("--transaction", "--response-key", "--namespace", "--pki-dir", "--yes"), "src/platform_pki/parser.py", "parser_reject_duplicates"),
    DuplicateOptionContract(("offline-csr", "approve"), ("--operation", "--request-id", "--input-dir", "--approval-key", "--output-dir", "--current-cert-file", "--namespace", "--pki-dir", "--yes"), "src/platform_pki/parser.py", "parser_reject_duplicates"),
    DuplicateOptionContract(("offline-csr", "sign"), ("--operation", "--request-id", "--input-dir", "--response-key", "--current-cert-file", "--intermediate-pass-file", "--issuer-safety-days", "--namespace", "--pki-dir", "--yes"), "src/platform_pki/parser.py", "parser_reject_duplicates"),
    DuplicateOptionContract(("certificate-export", "publish"), _CERTIFICATE_EXPORT_DUPLICATES, "bashly/platform-pki-certificate-export/src/initialize.sh"),
    DuplicateOptionContract(("certificate-export", "resolve"), _CERTIFICATE_EXPORT_DUPLICATES, "bashly/platform-pki-certificate-export/src/initialize.sh"),
    DuplicateOptionContract(("csr-candidate", "verify"), ("--request-id", "--format", "--namespace", "--pki-dir"), "src/platform_pki/parser.py", "parser_reject_duplicates"),
    DuplicateOptionContract(("csr-candidate", "finalize"), _CANDIDATE_DECISION_DUPLICATES, "src/platform_pki/parser.py", "parser_reject_duplicates"),
    DuplicateOptionContract(("csr-candidate", "abandon"), _CANDIDATE_DECISION_DUPLICATES, "src/platform_pki/parser.py", "parser_reject_duplicates"),
    DuplicateOptionContract(("service-issue",), _CSR_INPUT_FLAGS, "bashly/platform-pki-service-issue/src/root_command.sh"),
    DuplicateOptionContract(("service-renew",), _CSR_INPUT_FLAGS, "bashly/platform-pki-service-renew/src/root_command.sh"),
    DuplicateOptionContract(("service-renew",), _CSR_INPUT_FLAGS, "src/platform_pki/parser.py", "parser_reject_duplicates"),
    DuplicateOptionContract(("service-recover",), ("--transaction", "--namespace", "--pki-dir", "--yes"), "src/platform_pki/parser.py", "parser_reject_duplicates"),
    DuplicateOptionContract(("custody-report",), ("--namespace", "--pki-dir", "--format"), "bashly/platform-pki-custody-report/src/root_command.sh"),
    DuplicateOptionContract(("ca-passphrase-verify",), ("--namespace", "--pki-dir", "--root-pass-file", "--intermediate-pass-file"), "bashly/platform-pki-ca-passphrase-verify/src/root_command.sh"),
    DuplicateOptionContract(("ca-rollover", "migrate"), ("--namespace", "--pki-dir", "--backup-receipt", "--private-repo", "--yes", "--expected-root-sha256", "--expected-intermediate-sha256"), "bashly/platform-pki-ca-rollover/src/migrate_command.sh"),
    DuplicateOptionContract(("ca-rollover", "status"), ("--namespace", "--pki-dir", "--format"), "bashly/platform-pki-ca-rollover/src/status_command.sh"),
    DuplicateOptionContract(("ca-rollover", "prepare"), ("--namespace", "--pki-dir", "--type", "--backup-receipt", "--root-name", "--intermediate-name", "--org", "--country", "--root-days", "--intermediate-days", "--root-pass-file", "--intermediate-pass-file", "--issuer-safety-days", "--private-repo"), "bashly/platform-pki-ca-rollover/src/prepare_command.sh"),
    DuplicateOptionContract(("ca-rollover", "recover"), ("--namespace", "--pki-dir", "--transaction", "--action", "--yes"), "bashly/platform-pki-ca-rollover/src/recover_command.sh"),
)


OUTPUT_STATUS_COVERED_ROUTES = frozenset(
    {
        ("certificate-export", "resolve"),
        ("csr-candidate", "verify"),
        ("custody-report",),
        ("ca-rollover", "status"),
        ("print-cert",),
        ("list-expiry",),
        ("service-verify",),
    }
)

OUTPUT_STATUS_DEFERRED_ROUTES = frozenset(
    {
        ("init",),
        ("inventory-install",),
        ("csr-trust-install",),
        ("csr-recover",),
        ("offline-csr", "approve"),
        ("offline-csr", "sign"),
        ("certificate-export", "publish"),
        ("csr-candidate", "finalize"),
        ("csr-candidate", "abandon"),
        ("root-create",),
        ("intermediate-create",),
        ("service-issue",),
        ("service-renew",),
        ("service-recover",),
        ("export-ansible",),
        ("backup",),
        ("ca-passphrase-verify",),
        ("ca-rollover", "migrate"),
        ("ca-rollover", "prepare"),
        ("ca-rollover", "recover"),
    }
)


OUTPUT_STATUS_CONTRACTS = (
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
    OutputStatusContract(
        ("certificate-export", "resolve"),
        "exact-pinned-resolution",
        (StatusContract(0, "success", "the exact digest-pinned artifact was resolved"),),
        "absolute-path-or-canonical-json-line",
        "empty",
        True,
        None,
        (
            ("src/platform_pki/certificate_export.py", "print(absolute)"),
            ("src/platform_pki/certificate_export.py", '"kind": "certificate-export-resolution"'),
        ),
        (("tests/pki/test_certificate_export.py", "test_publish_bridges_real_csr_response_and_resolves_only_exact_pin"),),
    ),
    OutputStatusContract(
        ("csr-candidate", "verify"),
        "authenticated-candidate-status",
        (StatusContract(0, "success", "authenticated historical candidate status was rendered"),),
        "ordered-key-value-or-canonical-json-line",
        "empty",
        True,
        None,
        (
            ("src/platform_pki/csr_candidate.py", "print(json.dumps(values, sort_keys=True, separators=(\",\", \":\")))"),
            ("src/platform_pki/csr_candidate.py", "print(f\"state={state}\")"),
            ("src/platform_pki/csr_candidate.py", 'print("live_state_claimed=false")'),
        ),
        (("tests/pki/test_csr_candidate.py", "test_verify_finalize_and_exact_rerun"),),
    ),
    OutputStatusContract(
        ("custody-report",),
        "read-only-custody-report",
        (
            StatusContract(0, "success", "the report contains no structural findings"),
            StatusContract(2, "semantic", "the report contains one or more findings"),
        ),
        "stable-text-report-or-canonical-json-line",
        "empty",
        True,
        None,
        (
            ("src/platform_pki/custody_report.py", '"status": "findings" if report.findings else "ok"'),
            ("src/platform_pki/custody_report.py", 'return 2 if report.findings else 0'),
        ),
        (
            ("tests/pki/test_custody_report.py", "test_clean_generation_reports_match_frozen_oracle_bytes"),
            ("tests/pki/test_custody_report.py", "test_findings_report_matches_frozen_oracle_bytes"),
        ),
    ),
    OutputStatusContract(
        ("ca-rollover", "status"),
        "operational-rollover-status",
        (
            StatusContract(0, "success", "generation state is ready"),
            StatusContract(1, "semantic", "migration or a prepared rollover requires an operator action"),
            StatusContract(2, "semantic", "recovery or layout repair is required"),
        ),
        "ordered-key-value-or-canonical-json-line",
        "empty",
        True,
        None,
        (
            ("src/platform_pki/ca_rollover_status.py", '"status": "ready"'),
            ("src/platform_pki/ca_rollover_status.py", '"status": "prepared"'),
            ("src/platform_pki/ca_rollover_status.py", '"status":"recovery-required"'),
        ),
        (
            ("tests/pki/test_ca_rollover_status_python.py", "test_python_status_recovery_matches_frozen_oracle"),
            ("tests/pki/test_ca_rollover_status_python.py", "test_python_status_layouts_match_frozen_oracle"),
            ("tests/pki/test_ca_rollover_status_python.py", "test_python_status_prepared_root_matches_frozen_oracle"),
            ("tests/pki/test_ca_rollover_status.py", "test_status_reports_ready_generation"),
        ),
    ),
)


RUNTIME_DEPENDENCY_CONTRACTS = (
    RuntimeDependencyContract(
        ("print-cert",), "openssl", "invoked", "certificate rendering and issuer validation",
        "OpenSSL certificate inspection and verification",
        "src/platform_pki/print_cert.py", '"openssl",\n                "x509"',
    ),
    RuntimeDependencyContract(
        ("list-expiry",), "openssl", "invoked", "certificate expiry inspection and issuer validation",
        "OpenSSL certificate inspection and verification",
        "src/platform_pki/list_expiry.py", '("openssl", "x509", "-in", certificate, "-noout", "-enddate")',
    ),
    RuntimeDependencyContract(
        ("service-verify",), "openssl", "invoked", "certificate, key, extension, and chain verification",
        "OpenSSL certificate inspection and verification",
        "src/platform_pki/service_verify.py", '(\n                "openssl",\n                "verify",',
    ),
    *(
        RuntimeDependencyContract(
            (route,), "flock", "checked-only", "operational preflight",
            "PATH compatibility check; locking itself uses Python fcntl.flock",
            f"src/platform_pki/{route.replace('-', '_')}.py", 'require_program("flock", environment)',
        )
        for route in ("print-cert", "list-expiry", "service-verify")
    ),
    *(
        RuntimeDependencyContract(
            route, "fcntl.flock", "platform-capability", "operation lock acquisition",
            "nonblocking advisory locks over persistent lock files",
            "src/platform_pki/locks.py", "fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)",
        )
        for route in sorted(OUTPUT_STATUS_COVERED_ROUTES)
    ),
    RuntimeDependencyContract(
        ("list-expiry",), "date", "invoked", "certificate expiry conversion",
        "GNU date UTC parsing with -d", "src/platform_pki/list_expiry.py",
        '("date", "-u", "-d", not_after, "+%s")',
    ),
    RuntimeDependencyContract(
        ("list-expiry",), "sed", "invoked", "notAfter prefix removal",
        "stream transformation compatible with sed s/^notAfter=//",
        "src/platform_pki/list_expiry.py", '("sed", "s/^notAfter=//")',
    ),
    RuntimeDependencyContract(
        ("service-verify",), "cmp", "invoked", "managed key/certificate comparison",
        "quiet byte comparison", "src/platform_pki/service_verify.py",
        '("cmp", "-s", cert_public, key_public)',
    ),
    RuntimeDependencyContract(
        ("service-verify",), "grep", "invoked", "certificate extension validation",
        "fixed-string matching", "src/platform_pki/service_verify.py",
        '("grep", "-F", expected)',
    ),
    *(
        RuntimeDependencyContract(
            route, program, "invoked", "authenticated CSR history validation",
            capability, "src/platform_pki/csr_history.py", fragment,
        )
        for route in (("certificate-export", "resolve"), ("csr-candidate", "verify"))
        for program, capability, fragment in (
            ("openssl", "certificate profile, key, metadata, and chain validation", '(\n                    "openssl",\n                    "x509" if certificate else "req",'),
            ("ssh-keygen", "OpenSSH detached-signature verification", '(\n                    "ssh-keygen",'),
        )
    ),
    *(
        RuntimeDependencyContract(
            route, "procfs", "platform-capability", "descriptor-pinned validation and output",
            "Linux /proc/self/fd descriptor paths",
            source, fragment,
        )
        for route, source, fragment in (
            (("certificate-export", "resolve"), "src/platform_pki/certificate_export.py", 'f"/proc/self/fd/{artifact.fileno()}"'),
            (("csr-candidate", "verify"), "src/platform_pki/csr_history.py", 'f"/proc/self/fd/{allowed.fileno()}"'),
            (("ca-rollover", "status"), "src/platform_pki/ca_rollover_status.py", 'path = f"/proc/self/fd/{descriptor}"'),
        )
    ),
    *(
        RuntimeDependencyContract(
            ("custody-report",), program, "optional-evidence", "storage-encryption evidence collection",
            capability, "src/platform_pki/custody_report.py", fragment,
        )
        for program, capability, fragment in (
            ("findmnt", "mount source discovery", 'shutil.which("findmnt", path=path)'),
            ("lsblk", "block-device ancestry and filesystem-type discovery", 'shutil.which("lsblk", path=path)'),
        )
    ),
    RuntimeDependencyContract(
        ("ca-rollover", "status"), "openssl", "invoked", "authority observables and prepared chain validation",
        "OpenSSL certificate inspection and verification",
        "src/platform_pki/ca_rollover_status.py", '("openssl", "x509", "-in", path, "-noout", "-fingerprint", "-sha256")',
    ),
    RuntimeDependencyContract(
        ("ca-rollover", "status"), "date", "invoked", "authority expiry conversion",
        "GNU date UTC parsing with -d", "src/platform_pki/ca_rollover_status.py",
        '"-d",\n            enddate.removeprefix("notAfter="),',
    ),
    RuntimeDependencyContract(
        ("ca-rollover", "status"), "flock", "checked-only", "operational preflight",
        "PATH compatibility check; locking itself uses Python fcntl.flock",
        "src/platform_pki/ca_rollover_status.py", 'require_program("flock", environment)',
    ),
)


CURRENT_INSTALLED_ASSET_CONTRACTS = (
    InstalledAssetContract(
        "templates/pki/services.yml.example",
        0o644,
        (("init",),),
        (
            'PLATFORM_TOOLS_TEMPLATE_DIR + "/pki"',
            'package-or-archive-relative checkout + "/templates/pki"',
            'PLATFORM_TOOLS_SHARE_DIR-or-XDG-user-share + "/templates/pki"',
            '"/usr/local/share/platform-tools/templates/pki"',
        ),
        "initialization",
        (
            ("src/platform_pki/init.py", 'candidates.append(f"{explicit}/pki")'),
            ("src/platform_pki/init.py", 'f"{_checkout_directory()}/templates/pki"'),
            ("src/platform_pki/init.py", 'f"{environment.get(\'PLATFORM_TOOLS_SHARE_DIR\') or _user_share(environment)}/templates/pki"'),
            ("src/platform_pki/init.py", '"/usr/local/share/platform-tools/templates/pki"'),
            ("src/platform_pki/init.py", 'source = f"{template_directory}/services.yml.example"'),
            ("Makefile", 'chmod 644 "$(SHARE_DIR)"/templates/pki/*'),
        ),
        (("tests/test_installed_tools.py", "test_installed_pki_shared_asset_lookup"),),
    ),
)


HISTORICAL_ORACLE_ASSET_CONTRACTS = (
    HistoricalOracleAssetContract(
        "tests/pki/oracles/final-bash-source/lib/platform-pki-common.sh",
        0o644,
        (("print-cert",), ("list-expiry",), ("service-verify",)),
        (("tests/pki/oracles/final-bash-source/SHA256SUMS", "dee644be8ab6236cb368a553493f55b53a90c3aead291550f7e635c080a5494f  lib/platform-pki-common.sh"),),
        (
            ("tests/pki/test_print_cert.py", "test_frozen_oracle_matches_recorded_provenance"),
            ("tests/pki/test_list_expiry.py", "test_frozen_oracle_matches_recorded_provenance"),
            ("tests/pki/test_service_verify.py", "test_frozen_oracle_matches_recorded_provenance"),
            ("tests/pki/test_ca_rollover_status_python.py", "test_frozen_status_oracle_matches_recorded_provenance_and_modes"),
        ),
    ),
)


def _fields(value: str) -> tuple[str, ...]:
    return tuple(value.split())


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
        "src/platform_pki/root_create.py",
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
    RecordContract("root bootstrap journal", 3, "literal root bootstrap journal", "src/platform_pki/root_create.py", ROOT_BOOTSTRAP_JOURNAL_FIELDS),
    RecordContract("root bootstrap recovery journal", 3, "C-locale recovery journal", "bashly/platform-pki-ca-rollover/src/recover_command.sh", ROOT_BOOTSTRAP_RECOVERY_FIELDS),
    RecordContract(
        "intermediate bootstrap journal",
        3,
        "literal intermediate bootstrap journal",
        "src/platform_pki/intermediate_create.py",
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
    RecordContract("CSR response", 1, "literal Python CSR response", "src/platform_pki/csr_protocol.py", CANDIDATE_RESPONSE_FIELDS),
    RecordContract("CSR candidate", 1, "literal Python CSR candidate", "src/platform_pki/csr_protocol.py", CANDIDATE_RECORD_FIELDS),
    RecordContract("CSR replay request", 1, "literal CSR replay request", "lib/platform-pki-csr-sign.sh", CSR_REPLAY_REQUEST_FIELDS),
    RecordContract("CSR replay nonce", 1, "literal CSR replay nonce", "lib/platform-pki-csr-sign.sh", CSR_REPLAY_NONCE_FIELDS),
    RecordContract("CSR signing terminal", 1, "literal CSR signing terminal", "lib/platform-pki-csr-sign.sh", CSR_TERMINAL_FIELDS),
    RecordContract(
        "certificate export manifest",
        1,
        "literal Python certificate export manifest",
        "src/platform_pki/csr_history.py",
        CANDIDATE_ARTIFACT_FIELDS,
    ),
    RecordContract("deployment evidence", 1, "literal Python deployment evidence", "src/platform_pki/csr_history.py", CANDIDATE_DEPLOYMENT_FIELDS),
    RecordContract("active candidate", 1, "literal Python active candidate", "src/platform_pki/csr_history.py", CANDIDATE_ACTIVE_FIELDS),
    RecordContract("candidate outcome", 1, "literal Python candidate outcome", "src/platform_pki/csr_history.py", CANDIDATE_DECISION_FIELDS),
    RecordContract(
        "candidate finalization journal",
        1,
        "literal Python candidate finalization journal",
        "src/platform_pki/csr_recovery.py",
        CANDIDATE_JOURNAL_FIELDS,
    ),
    RecordContract(
        "managed service transaction journal",
        1,
        "literal Python service transaction",
        "src/platform_pki/service_transaction.py",
        SERVICE_TRANSACTION_FIELDS,
    ),
    RecordContract(
        "managed service retained transaction",
        1,
        "literal Python retained service transaction",
        "src/platform_pki/service_transaction.py",
        SERVICE_RETAINED_TRANSACTION_FIELDS,
    ),
    RecordContract(
        "managed service retained terminal",
        1,
        "literal Python retained service terminal",
        "src/platform_pki/service_transaction.py",
        SERVICE_RETAINED_TERMINAL_FIELDS,
    ),
    RecordContract(
        "managed service retained rollback completion",
        1,
        "literal Python retained service rollback completion",
        "src/platform_pki/service_transaction.py",
        SERVICE_RETAINED_ROLLBACK_FIELDS,
    ),
    RecordContract("legacy migration journal", 2, "literal migration journal", "bashly/platform-pki-ca-rollover/src/migrate_command.sh", LEGACY_MIGRATION_JOURNAL_FIELDS),
    RecordContract("legacy migration recovery journal", 2, "C-locale recovery journal", "bashly/platform-pki-ca-rollover/src/recover_command.sh", LEGACY_MIGRATION_RECOVERY_FIELDS),
    RecordContract("legacy migration checkpoint journal", 2, "C-locale recovery checkpoint", "bashly/platform-pki-ca-rollover/src/recover_command.sh", LEGACY_MIGRATION_CHECKPOINT_FIELDS),
    RecordContract("rollover preparation journal", 5, "C-locale preparation journal", "bashly/platform-pki-ca-rollover/src/prepare_command.sh", ROLLOVER_PREPARE_JOURNAL_FIELDS),
    RecordContract("rollover prepared-state manifest", 1, "literal prepared-state manifest", "bashly/platform-pki-ca-rollover/src/prepare_command.sh", ROLLOVER_PREPARED_MANIFEST_FIELDS),
)


_CA_RECOVERY = "bashly/platform-pki-ca-rollover/src/recover_command.sh"
_CSR_RECOVERY = "src/platform_pki/csr_recover.py"

RECOVERY_CONTRACTS = (
    RecoveryContract(
        "root bootstrap",
        "root-bootstrap",
        3,
        "platform-pki ca-rollover recover",
        "src/platform_pki/root_create.py",
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
        "src/platform_pki/intermediate_create.py",
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
            ("route", _CSR_RECOVERY, "_recover_signing_locked"),
            ("rollback-pre-commit", _CSR_RECOVERY, "_recover_uncommitted_signing"),
            ("resume-post-commit", _CSR_RECOVERY, "_recover_committed_signing"),
        ),
    ),
    RecoveryContract(
        "candidate finalization",
        "csr-finalize",
        1,
        "platform-pki csr-recover",
        "src/platform_pki/csr_recovery.py",
        ("resume",),
        (
            ("route", _CSR_RECOVERY, "_recover_finalization_locked"),
            ("resume", _CSR_RECOVERY, "_recover_finalization_locked"),
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
        "root bootstrap writer", ("root-bootstrap",), (3,), "src/platform_pki/root_create.py", "checkpoint",
        ROOT_FAULT_VARIABLES,
        (CheckpointCategory("pre-commit", ROOT_FAULT_CHECKPOINTS),),
        (), ("rollback",),
    ),
    FaultHookContract(
        "intermediate bootstrap writer", ("intermediate-bootstrap",), (3,), "src/platform_pki/intermediate_create.py", "checkpoint",
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
        "candidate finalization writer", ("csr-finalize",), (1,), "src/platform_pki/csr_candidate.py", "fault",
        (),
        (CheckpointCategory("pre-journal", ("outcome-staged", "active-staged")),),
        (), ("cleanup",),
    ),
    FaultHookContract(
        "candidate finalization recovery", ("csr-finalize",), (1,), "src/platform_pki/csr_recover.py", "CSR_FINALIZATION_RECOVERY_CHECKPOINTS",
        ("PLATFORM_PKI_CANDIDATE_CRASH_AT", "PLATFORM_PKI_CANDIDATE_SIGNAL_AT", "PLATFORM_PKI_CANDIDATE_FAIL_AT"),
        (CheckpointCategory("resume-only", CSR_FINALIZATION_RECOVERY_CHECKPOINTS),),
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
