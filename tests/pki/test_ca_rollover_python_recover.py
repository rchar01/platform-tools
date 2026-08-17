from __future__ import annotations

import os
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

import pytest

from src.platform_pki import ca_rollover_recover as recovery
from src.platform_pki import ca_rollover_recovery as recovery_schema
from src.platform_pki.errors import ApplicationError
from src.platform_pki.filesystem import (
    FileIdentity,
    FilesystemIdentityError,
    OpenedDirectory,
    identity_at,
)
from src.platform_pki.persisted_identity import (
    parse_file_identity,
    serialize_file_identity,
)
from src.platform_pki.publication import (
    PublicationReplacementAmbiguousError,
    replace_exact,
    unlink_exact,
)

from ..harness import ProcessResult
from .conftest import RolloverTools, RolloverWorkspace
from .migration_harness import (
    DifferentialResult,
    rebase_openssl_config,
    run_differential_case,
    snapshot_state,
)
from .test_ca_rollover_migrate import (
    _certificate_fingerprint,
    _crash_migration,
    _migration_command,
    _migration_inputs,
)
from .test_ca_rollover_prepare_recovery import (
    ROOT_DB_RELATIVES,
    _crash_after_staged,
    _crash_prepare,
    _read_strict_record,
    _root_db_path,
)
from .test_root_create import (
    ROOT_BOUNDARIES,
    ROOT_CREATE_ORACLE,
    ROOT_CREATE_ORACLE_LIB,
)


pytestmark = pytest.mark.pki

REPOSITORY = Path(__file__).resolve().parents[2]
FROZEN_BASH_ROLLOVER = (
    REPOSITORY
    / "tests/pki/oracles/platform-pki-ca-rollover/platform-pki-ca-rollover"
)
FROZEN_BASH_LIBRARY = FROZEN_BASH_ROLLOVER.parent / "lib"
UNIFIED_PLATFORM_PKI = REPOSITORY / "bin/platform-pki"

_ROOT_BOOTSTRAP_TOKENS = (
    (re.compile(r"root-bootstrap-[0-9]{8}-[0-9]{6}-[0-9]+"), "<ROOT-BOOTSTRAP>"),
)
_INTERMEDIATE_BOOTSTRAP_TOKENS = (
    (
        re.compile(r"intermediate-bootstrap-[0-9]{8}-[0-9]{6}-[0-9]+"),
        "<INTERMEDIATE-BOOTSTRAP>",
    ),
    (
        re.compile(r"\.platform-pki-intermediate-create\.[A-Za-z0-9_-]{6}"),
        "<INTERMEDIATE-CREATE-STAGE>",
    ),
)
_LEGACY_MIGRATION_TOKENS = (
    (re.compile(r"migrate-[0-9]{8}-[0-9]{6}-[0-9]+"), "<MIGRATION>"),
    (re.compile(r"backup-session-[0-9a-f]{32}"), "<BACKUP-SESSION>"),
    (
        re.compile(
            r"platform-pki-[0-9]{8}-[0-9]{6}\.tar\.gz(?:\.receipt)?"
        ),
        "<BACKUP-ARTIFACT>",
    ),
)
_PREPARATION_TOKENS = (
    (
        re.compile(r"prepare-intermediate-[0-9]{8}-[0-9]{6}-[0-9]+"),
        "<INTERMEDIATE-PREPARATION>",
    ),
    (re.compile(r"backup-session-[0-9a-f]{32}"), "<BACKUP-SESSION>"),
    (
        re.compile(
            r"platform-pki-[0-9]{8}-[0-9]{6}\.tar\.gz(?:\.receipt)?"
        ),
        "<BACKUP-ARTIFACT>",
    ),
)

_FULL_IDENTITY = re.compile(
    r"(?P<object>[0-9]+:[0-9]+):(?P<uid>[0-9]+):(?P<mode>[0-7]+):"
    r"(?P<links>[0-9]+):(?P<size>[0-9]+):"
    r"(?P<mtime>[0-9]{4}-.+ [+-][0-9]{4}):(?P<ctime>[0-9]{4}-.+ [+-][0-9]{4}):"
    r"(?P<kind>regular empty file|regular file|directory)"
)
_OBJECT_IDENTITY = re.compile(
    r"(?P<object>[0-9]+:[0-9]+):(?P<uid>[0-9]+):(?P<mode>[0-7]+):"
    r"(?P<links>[0-9]+):(?P<size>[0-9]+):"
    r"(?P<kind>regular empty file|regular file|directory)"
)
_DIRECTORY_IDENTITY = re.compile(
    r"(?P<object>[0-9]+:[0-9]+):(?P<metadata>[0-9]+:[0-7]+):directory"
)
_SIMPLE_IDENTITY = re.compile(r"(?P<object>[0-9]+:[0-9]+)")

_TERMINAL_IDENTITY_FIELDS = frozenset({"journal_identity", "marker_identity"})
_ROOT_BOOTSTRAP_IDENTITY_FIELDS = _TERMINAL_IDENTITY_FIELDS | frozenset(
    {
        "authority_identity",
        "stage_identity",
        "transaction_identity",
        "reservation_identity",
        "reservation_reserved_identity",
        "reservation_consumed_identity",
        "reservation_abandoned_identity",
        "bootstrap_identity",
    }
)
_INTERMEDIATE_BOOTSTRAP_IDENTITY_FIELDS = _TERMINAL_IDENTITY_FIELDS | frozenset(
    {
        "intermediate_identity",
        "stage_identity",
        "root_stage_identity",
        "transaction_identity",
        "reservation_identity",
        "reservation_reserved_identity",
        "reservation_consumed_identity",
        "reservation_abandoned_identity",
        "active_identity",
        "bootstrap_identity",
        "bootstrap_rollback_identity",
        *(
            f"root_{key}_{suffix}_identity"
            for key in ROOT_DB_RELATIVES
            for suffix in ("pre", "post", "backup")
        ),
    }
)
_LEGACY_IDENTITY_FIELDS = _TERMINAL_IDENTITY_FIELDS | frozenset(
    {
        "root_source_identity",
        "intermediate_source_identity",
        "transaction_identity",
        "provenance_identity",
        "provenance_manifest_identity",
        "receipt_identity",
        "services_identity",
        "source_identity",
        "backup_session_original_identity",
        "backup_session_published_identity",
        "root_reservation_original_identity",
        "root_reservation_reserved_identity",
        "root_reservation_consumed_identity",
        "root_reservation_rollback_identity",
        "intermediate_reservation_original_identity",
        "intermediate_reservation_reserved_identity",
        "intermediate_reservation_consumed_identity",
        "intermediate_reservation_rollback_identity",
        "root_config_original_identity",
        "root_config_published_identity",
        "root_config_rollback_identity",
        "root_config_backup_identity",
        "intermediate_config_original_identity",
        "intermediate_config_published_identity",
        "intermediate_config_rollback_identity",
        "intermediate_config_backup_identity",
        "issuer_ledger_identity",
        "quarantine_ledger_identity",
        "active_original_identity",
        "active_published_identity",
    }
)
_PREPARATION_IDENTITY_FIELDS = _TERMINAL_IDENTITY_FIELDS | frozenset(
    field
    for field in (
        *recovery_schema.ROLLOVER_PREPARE_DECLARED_FIELDS,
        *recovery_schema.ROLLOVER_PREPARE_RUNTIME_IDENTITY_FIELDS,
    )
    if field.endswith("_identity")
)


@dataclass(frozen=True)
class _RecoveryNormalization:
    tokens: tuple[tuple[re.Pattern[str], str], ...]
    identity_fields: frozenset[str]
    dynamic_identity_size_fields: frozenset[str]
    dynamic_fields: frozenset[str]
    generated_paths: tuple[re.Pattern[str], ...] = ()
    dynamic_text_paths: tuple[re.Pattern[str], ...] = ()
    private_metadata_paths: tuple[re.Pattern[str], ...] = ()
    manifest_paths: tuple[re.Pattern[str], ...] = ()
    generated_manifest_rows: tuple[re.Pattern[str], ...] = ()
    ledger_paths: tuple[re.Pattern[str], ...] = ()
    field_scoped_identity_fields: frozenset[str] = frozenset()


_BACKUP_DYNAMIC_FIELDS = frozenset(
    {
        "archive_sha256",
        "backup_device",
        "backup_inode",
        "created_at",
        "created_epoch",
        "private_metadata_sha256",
        "public_state_sha256",
        "session",
        "state_manifest_sha256",
    }
)
_ROOT_BOOTSTRAP_NORMALIZATION = _RecoveryNormalization(
    tokens=_ROOT_BOOTSTRAP_TOKENS,
    identity_fields=_ROOT_BOOTSTRAP_IDENTITY_FIELDS,
    dynamic_identity_size_fields=frozenset(
        {
            "reservation_identity",
            "reservation_reserved_identity",
            "reservation_consumed_identity",
            "reservation_abandoned_identity",
        }
    ),
    dynamic_fields=frozenset({"fingerprint_sha256"}),
    generated_paths=(
        re.compile(r"authorities/roots/g1/certs/root-ca\.crt"),
        re.compile(r"authorities/roots/g1/private/root-ca\.key"),
    ),
    # These identities can outlive unlinked objects whose inode is reused.
    field_scoped_identity_fields=frozenset(
        {"bootstrap_identity", "reservation_reserved_identity"}
    ),
)
_INTERMEDIATE_BOOTSTRAP_NORMALIZATION = _RecoveryNormalization(
    tokens=_INTERMEDIATE_BOOTSTRAP_TOKENS,
    identity_fields=_INTERMEDIATE_BOOTSTRAP_IDENTITY_FIELDS,
    dynamic_identity_size_fields=frozenset(
        {
            "reservation_identity",
            "reservation_reserved_identity",
            "reservation_consumed_identity",
            "reservation_abandoned_identity",
            "root_newcert_post_identity",
        }
    ),
    dynamic_fields=frozenset({"fingerprint_sha256"}),
    generated_paths=(
        re.compile(
            r"authorities/intermediates/g1-i1/(?:certs/(?:intermediate-ca|ca-chain)\.crt|"
            r"csr/intermediate-ca\.csr|private/intermediate-ca\.key)"
        ),
        re.compile(
            r"authorities/roots/g1/(?:index\.txt|newcerts/[^/]+\.pem)"
        ),
        re.compile(
            r"authorities/intermediates/<INTERMEDIATE-CREATE-STAGE>/root/"
            r"(?:index\.txt|newcerts/[^/]+\.pem)"
        ),
    ),
    dynamic_text_paths=(
        re.compile(
            r"authorities/intermediates/<INTERMEDIATE-CREATE-STAGE>/root/openssl\.cnf"
        ),
    ),
    # These identities outlive unlinked objects whose inode numbers can be reused.
    field_scoped_identity_fields=frozenset(
        {
            "bootstrap_identity",
            "reservation_reserved_identity",
            *(
                f"root_{key}_{suffix}_identity"
                for key in ROOT_DB_RELATIVES
                for suffix in ("pre", "backup")
            ),
        }
    ),
)
_LEGACY_NORMALIZATION = _RecoveryNormalization(
    tokens=_LEGACY_MIGRATION_TOKENS,
    identity_fields=_LEGACY_IDENTITY_FIELDS,
    dynamic_identity_size_fields=frozenset(
        {
            "root_config_original_identity",
            "root_config_published_identity",
            "root_config_rollback_identity",
            "root_config_backup_identity",
            "intermediate_config_original_identity",
            "intermediate_config_published_identity",
            "intermediate_config_rollback_identity",
            "intermediate_config_backup_identity",
            "backup_session_published_identity",
            "receipt_identity",
        }
    ),
    dynamic_fields=_BACKUP_DYNAMIC_FIELDS
    | frozenset(
        {
            "issuer_ledger_sha256",
            "provenance_manifest_sha256",
            "quarantine_ledger_sha256",
        }
    ),
    manifest_paths=(
        re.compile(r"legacy/(?:\.<MIGRATION>\.publish|<MIGRATION>)/provenance-manifest"),
    ),
    generated_manifest_rows=(
        re.compile(r"backup-session\.publish"),
        re.compile(r"baseline"),
        re.compile(r"(?:issuer|quarantine)-identities"),
        re.compile(
            r"(?:root|intermediate)-openssl\.(?:cnf|new|backup|rollback)"
        ),
        re.compile(
            r"(?:root|intermediate)-(?:reserved|consumed|abandoned)\.publish"
        ),
    ),
    dynamic_text_paths=(
        re.compile(
            r"(?:legacy/(?:\.<MIGRATION>\.publish|<MIGRATION>)|"
            r"state/rollover/<MIGRATION>)/"
            r"(?:root|intermediate)-openssl\.(?:cnf|new|backup|rollback)"
        ),
    ),
    ledger_paths=(
        re.compile(
            r"state/rollover/<MIGRATION>/(?:issuer-identities|quarantine-identities)"
        ),
        re.compile(
            r"legacy/(?:\.<MIGRATION>\.publish|<MIGRATION>)/"
            r"(?:issuer-identities|quarantine-identities)"
        ),
    ),
    private_metadata_paths=(
        re.compile(
            r"(?:legacy/(?:\.<MIGRATION>\.publish|<MIGRATION>)|"
            r"state/rollover/<MIGRATION>)/baseline"
        ),
    ),
)
_PREPARATION_NORMALIZATION = _RecoveryNormalization(
    tokens=_PREPARATION_TOKENS,
    identity_fields=_PREPARATION_IDENTITY_FIELDS,
    dynamic_identity_size_fields=frozenset(
        {
            "root_reservation_reserved_identity",
            "root_reservation_consumed_identity",
            "root_reservation_abandoned_identity",
            "intermediate_reservation_reserved_identity",
            "intermediate_reservation_consumed_identity",
            "intermediate_reservation_abandoned_identity",
            "backup_session_identity",
            "candidate_chain_identity",
            "candidate_intermediate_cert_identity",
            "candidate_intermediate_tree_manifest_identity",
            "candidate_root_tree_manifest_identity",
            "journal_identity",
            "long_manifest_identity",
            "long_tree_manifest_identity",
            "marker_identity",
            "pointer_identity",
            "receipt_identity",
            "root_stage_tree_manifest_identity",
            "root_newcert_post_identity",
            "root_newcert_source_identity",
            "stage_tree_manifest_identity",
            "transaction_tree_manifest_identity",
            "transaction_tree_manifest_pending_identity",
        }
    ),
    dynamic_fields=_BACKUP_DYNAMIC_FIELDS
    | frozenset(
        {
            "candidate_intermediate_cert_sha256",
            "candidate_intermediate_expiry",
            "candidate_intermediate_fingerprint",
            "candidate_intermediate_tree_manifest_sha256",
            "candidate_intermediate_tree_sha256",
            "candidate_chain_sha256",
            "created_at",
            "intermediate_expiry",
            "intermediate_fingerprint",
            "long_manifest_sha256",
            "long_tree_manifest_sha256",
            "root_stage_tree_manifest_sha256",
            "stage_tree_manifest_sha256",
            "transaction_tree_manifest_pending_sha256",
            "transaction_tree_manifest_sha256",
            "tree_manifest_sha256",
            "trust_bundle_sha256",
            "backup_state_sha256",
        }
    ),
    generated_paths=(
        re.compile(
            r"authorities/intermediates/g1-i2/(?:certs/(?:intermediate-ca|ca-chain)\.crt|"
            r"csr/intermediate-ca\.csr|private/intermediate-ca\.key)"
        ),
        re.compile(
            r"authorities/roots/g1/(?:index\.txt|newcerts/[^/]+\.pem)"
        ),
        re.compile(
            r"state/rollover/<INTERMEDIATE-PREPARATION>/stage/intermediate/"
            r"(?:certs/(?:intermediate-ca|ca-chain)\.crt|csr/intermediate-ca\.csr|"
            r"private/intermediate-ca\.key)"
        ),
        re.compile(
            r"state/rollover/<INTERMEDIATE-PREPARATION>/stage/root/"
            r"(?:index\.txt|newcerts/[^/]+\.pem)"
        ),
    ),
    dynamic_text_paths=(
        re.compile(r"authorities/intermediates/g1-i2/openssl\.cnf"),
        re.compile(
            r"state/rollover/<INTERMEDIATE-PREPARATION>/stage/"
            r"(?:root|intermediate)/openssl\.cnf"
        ),
    ),
    manifest_paths=(
        re.compile(
            r"state/rollover/\.<INTERMEDIATE-PREPARATION>\.transaction-tree\.[0-9]+"
        ),
        re.compile(
            r"state/rollover/<INTERMEDIATE-PREPARATION>/(?:stage-tree\.manifest|"
            r"rollover-state/(?:candidate-intermediate-tree|root-signing-stage-tree|tree)\.manifest)"
        ),
        re.compile(
            r"state/rollovers/<INTERMEDIATE-PREPARATION>/"
            r"(?:candidate-intermediate-tree|root-signing-stage-tree|tree)\.manifest"
        ),
    ),
    generated_manifest_rows=(
        re.compile(
            r"(?:(?:stage/)?intermediate/)?(?:certs/(?:intermediate-ca|ca-chain)\.crt|"
            r"csr/intermediate-ca\.csr|private/intermediate-ca\.key)"
        ),
        re.compile(
            r"(?:(?:stage/)?root/)?(?:index\.txt|newcerts/[^/]+\.pem)"
        ),
        re.compile(r"(?:(?:stage/)?(?:root|intermediate)/)?openssl\.cnf"),
        re.compile(r"backup-session\.publish"),
        re.compile(
            r"(?:root|intermediate)-(?:reserved|consumed|abandoned)(?:\.publish)?"
        ),
        re.compile(r"stage/(?:root|intermediate)/openssl\.cnf"),
        re.compile(r"(?:rollover-state/)?manifest"),
        re.compile(
            r"(?:rollover-state/)?(?:candidate-intermediate-tree|"
            r"root-signing-stage-tree|tree)\.manifest"
        ),
        re.compile(r"stage-tree\.manifest"),
        re.compile(r"active-rollover\.publish"),
    ),
    # These identities outlive unlinked objects whose inode numbers can be reused.
    field_scoped_identity_fields=frozenset(
        {
            "transaction_tree_manifest_identity",
            *(
                f"signing_{key}_pre_identity"
                for key in ROOT_DB_RELATIVES
                if key.endswith("_old")
            ),
        }
    ),
)


@pytest.fixture
def python_platform_pki() -> Path:
    return UNIFIED_PLATFORM_PKI


def _python_recover(
    tool: Path,
    workspace: RolloverWorkspace,
    transaction: str,
    action: str,
    environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> ProcessResult:
    return process_runner(
        [
            tool,
            "ca-rollover",
            "recover",
            "--namespace",
            workspace.namespace,
            "--transaction",
            transaction,
            "--action",
            action,
            "--yes",
        ],
        env=environment,
        timeout=120,
    )


def _replace_file_exact(source: Path, destination: Path) -> FileIdentity:
    source_identity = identity_at(source)
    destination_identity = identity_at(destination)
    assert isinstance(source_identity, FileIdentity)
    assert isinstance(destination_identity, FileIdentity)
    published: FileIdentity | None = None
    with (
        OpenedDirectory(source.parent) as source_parent,
        OpenedDirectory(destination.parent) as destination_parent,
    ):
        result = replace_exact(
            source_parent,
            source.name,
            source_identity,
            destination_parent,
            destination.name,
            destination_identity,
        )
        published = result.destination_identity
    assert published is not None
    return published


def _root_db_destination(
    workspace: RolloverWorkspace, record: dict[str, str], key: str
) -> Path:
    relative = ROOT_DB_RELATIVES[key].format(
        issued_serial=record["issued_serial"]
    )
    return workspace.pki / "authorities/roots/g1" / relative


def test_staged_publication_rejects_unauthorized_destination(tmp_path: Path) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    displaced = tmp_path / "displaced"
    source.write_bytes(b"source\n")
    source.chmod(0o600)
    destination.write_bytes(b"authorized\n")
    destination.chmod(0o600)
    source_identity = identity_at(source)
    authorized_destination = identity_at(destination)
    assert isinstance(source_identity, FileIdentity)
    assert isinstance(authorized_destination, FileIdentity)
    destination.rename(displaced)
    destination.write_bytes(b"hostile\n")
    destination.chmod(0o600)
    hostile_identity = identity_at(destination)

    with pytest.raises(
        ApplicationError,
        match="destination is not in a journaled identity state",
    ):
        recovery._publish_file(
            str(source),
            str(destination),
            source_identity,
            authorized_destination,
        )

    assert identity_at(source) == source_identity
    assert identity_at(destination) == hostile_identity
    assert destination.read_bytes() == b"hostile\n"


def test_staged_publication_preserves_ambiguity_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.write_bytes(b"source\n")
    source.chmod(0o600)
    destination.write_bytes(b"destination\n")
    destination.chmod(0o600)
    source_identity = identity_at(source)
    destination_identity = identity_at(destination)
    assert isinstance(source_identity, FileIdentity)
    assert isinstance(destination_identity, FileIdentity)

    def ambiguous(*_args: object, **_kwargs: object) -> None:
        raise PublicationReplacementAmbiguousError()

    monkeypatch.setattr(recovery, "replace_exact", ambiguous)
    with pytest.raises(PublicationReplacementAmbiguousError):
        recovery._publish_file(
            str(source),
            str(destination),
            source_identity,
            destination_identity,
        )


def test_control_write_translates_filesystem_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail(*_args: object, **_kwargs: object) -> None:
        raise FilesystemIdentityError()

    monkeypatch.setattr(recovery, "atomic_write_bytes", fail)
    with pytest.raises(
        ApplicationError,
        match="Recovery control record could not be published",
    ):
        recovery._write_control(str(tmp_path / "control"), b"value\n")


def test_control_write_translates_destination_inspection_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail(*_args: object, **_kwargs: object) -> None:
        raise FilesystemIdentityError()

    monkeypatch.setattr(OpenedDirectory, "identity_at", fail)
    with pytest.raises(
        ApplicationError,
        match="Recovery control record could not be published",
    ):
        recovery._write_control(str(tmp_path / "control"), b"value\n")


def _assert_root_bootstrap_recovery_and_retry(
    python_platform_pki: Path,
    workspace,
    environment: Mapping[str, str],
    tools,
    process_runner: Callable[..., ProcessResult],
) -> None:
    from . import test_root_create as root_create

    journal = workspace.pki / "state/rollover/journal"
    transaction = root_create.record(journal)["transaction"]
    result = _python_recover(
        python_platform_pki,
        workspace,
        transaction,
        "rollback",
        environment,
        process_runner,
    )

    assert result.status == 0, result
    assert result.stderr == ""
    terminal = root_create.record(journal)
    assert terminal["phase"] == "rolled-back"
    assert terminal["recovery_action"] == "rollback"
    assert terminal["recovery_step"] == "complete"
    assert terminal["committed"] == "true"
    assert not os.path.lexists(workspace.pki / "authorities/roots/g1")
    assert not os.path.lexists(workspace.pki / "state/bootstrap-root")
    assert not os.path.lexists(workspace.pki / "state/rollover/recovery-required")
    assert root_create.record(
        workspace.pki / "state/generation-reservations/g1"
    )["status"] == "abandoned"

    parsed = recovery_schema.parse_recovery_semantics(
        journal.read_bytes(), pki_dir=workspace.pki
    )
    assert isinstance(parsed, recovery_schema.RootBootstrapRecoveryRecord)
    assert parsed.committed and parsed.phase == "rolled-back"
    assert parsed.recovery_action is recovery_schema.RecoveryAction.ROLLBACK
    assert parsed.recovery_step == "complete"
    retried = root_create.create_root(
        process_runner,
        workspace,
        environment,
        tools,
        unencrypted=True,
    )
    assert retried.status == 0, retried
    assert root_create.record(workspace.pki / "state/bootstrap-root")["root"] == "g2"
    assert root_create.record(
        workspace.pki / "state/generation-reservations/g2"
    )["status"] == "consumed"


@pytest.mark.parametrize("boundary", ROOT_BOUNDARIES, ids=ROOT_BOUNDARIES)
def test_python_recovers_python_written_root_bootstrap_at_every_boundary(
    tmp_path: Path,
    python_platform_pki: Path,
    process_runner: Callable[..., ProcessResult],
    boundary: str,
) -> None:
    from . import test_root_create as root_create

    tools = root_create.tools()
    workspace = root_create.workspace(tmp_path / "root-bootstrap")
    environment = root_create.environment(tmp_path / "root-environment")
    root_create.initialize(process_runner, workspace, environment, tools)
    crashed = root_create.create_root(
        process_runner,
        workspace,
        dict(environment, PLATFORM_PKI_ROOT_CRASH_AT=boundary),
        tools,
        unencrypted=True,
    )
    assert crashed.status == 137
    _assert_root_bootstrap_recovery_and_retry(
        python_platform_pki,
        workspace,
        environment,
        tools,
        process_runner,
    )


@pytest.mark.parametrize("boundary", ROOT_BOUNDARIES, ids=ROOT_BOUNDARIES)
def test_python_recovers_frozen_bash_root_bootstrap_at_every_boundary(
    tmp_path: Path,
    python_platform_pki: Path,
    process_runner: Callable[..., ProcessResult],
    boundary: str,
) -> None:
    from . import test_root_create as root_create

    tools = root_create.tools()
    workspace = root_create.workspace(tmp_path / "root-bootstrap-bash")
    environment = root_create.environment(tmp_path / "root-bash-environment")
    environment["PLATFORM_TOOLS_LIB_DIR"] = os.fspath(ROOT_CREATE_ORACLE_LIB)
    root_create.initialize(process_runner, workspace, environment, tools)
    crashed = root_create.run(
        process_runner,
        [
            ROOT_CREATE_ORACLE,
            "--namespace",
            workspace.namespace,
            "--name",
            "Frozen Bash Root",
            "--org",
            "Platform Test",
            "--country",
            "PL",
            "--allow-unencrypted-root-key",
        ],
        dict(environment, PLATFORM_PKI_ROOT_CRASH_AT=boundary),
    )
    assert crashed.status == 137
    _assert_root_bootstrap_recovery_and_retry(
        python_platform_pki,
        workspace,
        environment,
        tools,
        process_runner,
    )


def test_python_recovers_intermediate_bootstrap_schema3(
    tmp_path: Path,
    python_platform_pki: Path,
    process_runner: Callable[..., ProcessResult],
) -> None:
    from . import test_intermediate_create as intermediate_create

    tools = intermediate_create.tools()
    workspace = intermediate_create.workspace(tmp_path / "intermediate-bootstrap")
    environment = intermediate_create.environment(tmp_path / "intermediate-environment")
    intermediate_create._bootstrap(process_runner, workspace, environment, tools)
    crashed = intermediate_create.run(
        process_runner,
        intermediate_create._create_command(workspace, tools),
        dict(
            environment,
            PLATFORM_PKI_INTERMEDIATE_CRASH_AT="after-bootstrap",
        ),
    )
    assert crashed.status == 137
    transaction = intermediate_create.record(
        workspace.pki / "state/rollover/journal"
    )["transaction"]

    result = process_runner(
        [
            python_platform_pki,
            "ca-rollover",
            "recover",
            "--namespace",
            workspace.namespace,
            "--transaction",
            transaction,
            "--action",
            "rollback",
            "--yes",
        ],
        env=environment,
        timeout=120,
    )

    assert result.status == 0, result
    assert result.stderr == ""
    assert intermediate_create.record(
        workspace.pki / "state/generation-reservations/g1-i1"
    )["status"] == "abandoned"


def test_python_recovers_legacy_migration_schema2(
    python_platform_pki: Path,
    rollover_tools: RolloverTools,
    legacy_rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> None:
    workspace = legacy_rollover_case_factory("python-legacy-recovery")
    command, _root_fingerprint, _intermediate_fingerprint = _migration_inputs(
        rollover_tools,
        workspace,
        backup_receipt_factory,
        isolated_environment,
        process_runner,
    )
    journal = _crash_migration(
        command,
        workspace,
        "after-root-rename",
        isolated_environment,
        process_runner,
    )

    result = _python_recover(
        python_platform_pki,
        workspace,
        journal["transaction"],
        "rollback",
        isolated_environment,
        process_runner,
    )

    assert result.status == 0, result
    assert result.stderr == ""
    assert (workspace.pki / "root-ca").is_dir()
    assert (workspace.pki / "intermediate-ca").is_dir()
    assert _read_strict_record(
        workspace.pki / "state/rollover/journal"
    )["committed"] == "true"


def test_python_legacy_recovery_rejects_unsafe_transaction_mode_without_change(
    python_platform_pki: Path,
    rollover_tools: RolloverTools,
    legacy_rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> None:
    workspace = legacy_rollover_case_factory("python-legacy-unsafe-transaction")
    command, _root_fingerprint, _intermediate_fingerprint = _migration_inputs(
        rollover_tools,
        workspace,
        backup_receipt_factory,
        isolated_environment,
        process_runner,
    )
    journal = _crash_migration(
        command,
        workspace,
        "after-root-rename",
        isolated_environment,
        process_runner,
    )
    transaction_directory = Path(journal["transaction_dir"])
    transaction_directory.chmod(0o750)
    before = snapshot_state(workspace.pki)

    result = _python_recover(
        python_platform_pki,
        workspace,
        journal["transaction"],
        "rollback",
        isolated_environment,
        process_runner,
    )

    assert result.status == 1, result
    assert result.stdout == ""
    assert result.stderr == (
        "[ERROR] Recovery transaction directory is missing, replaced, or unsafe\n"
    )
    assert snapshot_state(workspace.pki) == before


def test_python_resume_recovers_root_db_publication_before_journal(
    python_platform_pki: Path,
    rollover_tools: RolloverTools,
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> None:
    workspace = rollover_case_factory("python-root-db-resume-window")
    receipt = backup_receipt_factory(workspace)
    journal, record, transaction_directory = _crash_after_staged(
        rollover_tools,
        workspace,
        receipt,
        isolated_environment,
        process_runner,
    )
    key = "index"
    pending_environment = dict(isolated_environment)
    pending_environment["PLATFORM_PKI_RECOVER_CRASH_AT"] = (
        f"resume-root-db-{key}-pending"
    )
    pending = _python_recover(
        python_platform_pki,
        workspace,
        journal["transaction"],
        "resume",
        pending_environment,
        process_runner,
    )
    assert pending.status == 137, pending

    source = _root_db_path(transaction_directory, record, key)
    destination = _root_db_destination(workspace, record, key)
    published = _replace_file_exact(source, destination)
    source_identity = parse_file_identity(record[f"root_{key}_source_identity"])
    assert isinstance(source_identity, FileIdentity)
    assert published.state == source_identity.state

    done_environment = dict(isolated_environment)
    done_environment["PLATFORM_PKI_RECOVER_CRASH_AT"] = (
        f"resume-root-db-{key}-done"
    )
    done = _python_recover(
        python_platform_pki,
        workspace,
        journal["transaction"],
        "resume",
        done_environment,
        process_runner,
    )
    assert done.status == 137, done
    rewritten = _read_strict_record(workspace.pki / "state/rollover/journal")
    assert rewritten[f"root_{key}_post_identity"] == serialize_file_identity(
        published
    )

    result = _python_recover(
        python_platform_pki,
        workspace,
        journal["transaction"],
        "resume",
        isolated_environment,
        process_runner,
    )
    assert result.status == 0, result


def test_python_rollback_recovers_root_db_restoration_before_journal(
    python_platform_pki: Path,
    rollover_tools: RolloverTools,
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> None:
    workspace = rollover_case_factory("python-root-db-rollback-window")
    receipt = backup_receipt_factory(workspace)
    selected = _crash_prepare(
        rollover_tools,
        workspace,
        receipt,
        "intermediate",
        2,
        "after-root-db",
        isolated_environment,
        process_runner,
        "publish-root-db-newcert-done",
    )
    journal_path = workspace.pki / "state/rollover/journal"
    record = _read_strict_record(journal_path)
    transaction_directory = Path(record["transaction_dir"])
    key = "index"
    pending_environment = dict(isolated_environment)
    pending_environment["PLATFORM_PKI_RECOVER_CRASH_AT"] = (
        f"rollback-root-db-{key}-pending"
    )
    pending = _python_recover(
        python_platform_pki,
        workspace,
        selected["transaction"],
        "rollback",
        pending_environment,
        process_runner,
    )
    assert pending.status == 137, pending

    relative = ROOT_DB_RELATIVES[key].format(
        issued_serial=record["issued_serial"]
    )
    backup = transaction_directory / "stage/root-backup" / relative
    destination = _root_db_destination(workspace, record, key)
    restored = _replace_file_exact(backup, destination)
    backup_identity = parse_file_identity(record[f"root_{key}_backup_identity"])
    assert isinstance(backup_identity, FileIdentity)
    assert restored.state == backup_identity.state

    done_environment = dict(isolated_environment)
    done_environment["PLATFORM_PKI_RECOVER_CRASH_AT"] = (
        f"rollback-root-db-{key}-done"
    )
    done = _python_recover(
        python_platform_pki,
        workspace,
        selected["transaction"],
        "rollback",
        done_environment,
        process_runner,
    )
    assert done.status == 137, done
    rewritten = _read_strict_record(journal_path)
    assert rewritten[f"root_{key}_rollback_identity"] == serialize_file_identity(
        restored
    )

    result = _python_recover(
        python_platform_pki,
        workspace,
        selected["transaction"],
        "rollback",
        isolated_environment,
        process_runner,
    )
    assert result.status == 0, result


def test_python_recovers_rollover_prepare_and_receipt_only_cleanup(
    python_platform_pki: Path,
    rollover_tools: RolloverTools,
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    backup_receipt_factory: Callable[[RolloverWorkspace], Path],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> None:
    workspace = rollover_case_factory("python-prepare-recovery")
    receipt = backup_receipt_factory(workspace)
    journal, _record, _transaction_directory = _crash_after_staged(
        rollover_tools,
        workspace,
        receipt,
        isolated_environment,
        process_runner,
    )
    crash_environment = dict(isolated_environment)
    crash_environment["PLATFORM_PKI_RECOVER_CRASH_AT"] = "terminal-journal-done"

    crashed = _python_recover(
        python_platform_pki,
        workspace,
        journal["transaction"],
        "resume",
        crash_environment,
        process_runner,
    )
    assert crashed.status == 137, crashed
    assert not (workspace.pki / "state/rollover/journal").exists()
    assert (workspace.pki / "state/rollover/recovery-required").is_file()

    result = _python_recover(
        python_platform_pki,
        workspace,
        journal["transaction"],
        "resume",
        isolated_environment,
        process_runner,
    )

    assert result.status == 0, result
    assert result.stderr == ""
    assert not (workspace.pki / "state/rollover/recovery-required").exists()
    assert (workspace.pki / "state/active-rollover").is_file()


def _copied_workspace(root: Path) -> RolloverWorkspace:
    return RolloverWorkspace(
        root=root,
        namespace=root / "ns",
        pki=root / "ns/pki",
        private_repo=root / "private",
        passphrase_file=root / "passphrase",
    )


def _replace_dynamic_tokens(
    value: str, normalization: _RecoveryNormalization
) -> str:
    for pattern, replacement in normalization.tokens:
        value = pattern.sub(replacement, value)
    return value


def _normalize_persisted_identity(
    value: str,
    object_labels: dict[str, str],
    *,
    dynamic_size: bool = False,
    object_label: str | None = None,
) -> str:
    for pattern in (
        _FULL_IDENTITY,
        _OBJECT_IDENTITY,
        _DIRECTORY_IDENTITY,
        _SIMPLE_IDENTITY,
    ):
        match = pattern.fullmatch(value)
        if match is None:
            continue
        object_key = match["object"]
        label = object_label or object_labels.setdefault(
            object_key, f"<OBJECT-{len(object_labels) + 1}>"
        )
        if pattern is _FULL_IDENTITY:
            size = "<DYNAMIC-SIZE>" if dynamic_size else match["size"]
            return (
                f"{label}:{match['uid']}:{match['mode']}:{match['links']}:{size}:"
                f"<MTIME>:<CTIME>:"
                f"{match['kind']}"
            )
        if pattern is _DIRECTORY_IDENTITY:
            return f"{label}:{match['metadata']}:directory"
        if pattern is _SIMPLE_IDENTITY:
            return label
        size = "<DYNAMIC-SIZE>" if dynamic_size else match["size"]
        return (
            f"{label}:{match['uid']}:{match['mode']}:{match['links']}:{size}:"
            f"{match['kind']}"
        )
    raise ValueError("declared persisted identity field is malformed")


def _normalize_manifest(
    relative: str,
    content: bytes,
    normalization: _RecoveryNormalization,
) -> bytes:
    text = content.decode("ascii")
    labels: dict[str, str] = {}
    rows = []
    for line in text.splitlines():
        columns = line.split("|")
        if len(columns) != 4:
            raise ValueError(f"Declared recovery manifest is malformed: {relative}")
        kind, path, identity, digest = columns
        dynamic_row = any(
            pattern.fullmatch(path)
            for pattern in normalization.generated_manifest_rows
        )
        identity = _normalize_persisted_identity(
            identity, labels, dynamic_size=dynamic_row
        )
        if dynamic_row and digest not in {"-", "secret"}:
            digest = f"<GENERATED-SHA256:{path}>"
        rows.append("|".join((kind, path, identity, digest)))
    return ("\n".join(rows) + "\n").encode("ascii")


def _normalize_identity_ledger(relative: str, content: bytes) -> bytes:
    labels: dict[str, str] = {}
    rows = []
    for line in content.decode("ascii").splitlines():
        columns = line.split("|")
        if len(columns) not in {2, 3}:
            raise ValueError(f"Declared recovery identity ledger is malformed: {relative}")
        for index in range(1, len(columns)):
            if columns[index] not in {"absent", "none"}:
                columns[index] = _normalize_persisted_identity(
                    columns[index], labels
                )
        rows.append("|".join(columns))
    return ("\n".join(rows) + ("\n" if rows else "")).encode("ascii")


def _normalize_private_metadata(
    relative: str,
    content: bytes,
    normalization: _RecoveryNormalization,
    roots: tuple[bytes, ...],
) -> bytes:
    labels: dict[str, str] = {}
    rows = []
    for line in content.decode("ascii").splitlines():
        if line.startswith("public_state_sha256="):
            rows.append("public_state_sha256=<DYNAMIC:public_state_sha256>")
            continue
        if not line.startswith("private_metadata="):
            raise ValueError(f"Declared private metadata record is malformed: {relative}")
        columns = line.removeprefix("private_metadata=").split("|")
        if len(columns) != 8:
            raise ValueError(f"Declared private metadata row is malformed: {relative}")
        for root in roots:
            columns[0] = columns[0].replace(os.fsdecode(root), "<WORKSPACE>")
        columns[0] = _replace_dynamic_tokens(columns[0], normalization)
        object_key = f"{columns[1]}:{columns[2]}"
        columns[1] = labels.setdefault(
            object_key, f"<OBJECT-{len(labels) + 1}>"
        )
        del columns[2]
        columns[-2:] = ["<MTIME>", "<CTIME>"]
        rows.append(f"private_metadata={'|'.join(columns)}")
    return ("\n".join(rows) + "\n").encode("ascii")


def _recovery_content_normalizer(
    normalization: _RecoveryNormalization, *roots: Path
):
    encoded_roots = tuple(os.fsencode(root) for root in roots)

    def normalize(relative: str, content: bytes) -> bytes:
        normalized_relative = _replace_dynamic_tokens(relative, normalization)
        if any(
            pattern.fullmatch(normalized_relative)
            for pattern in normalization.generated_paths
        ):
            return b"<GENERATED-RECOVERY-CONTENT>\n"
        if any(
            pattern.fullmatch(normalized_relative)
            for pattern in normalization.manifest_paths
        ):
            return _normalize_manifest(normalized_relative, content, normalization)
        if any(
            pattern.fullmatch(normalized_relative)
            for pattern in normalization.ledger_paths
        ):
            return _normalize_identity_ledger(normalized_relative, content)
        if any(
            pattern.fullmatch(normalized_relative)
            for pattern in normalization.private_metadata_paths
        ):
            return _normalize_private_metadata(
                normalized_relative, content, normalization, encoded_roots
            )
        try:
            text = content.decode("ascii")
        except UnicodeDecodeError:
            return content
        if any(
            pattern.fullmatch(normalized_relative)
            for pattern in normalization.dynamic_text_paths
        ):
            text = _replace_dynamic_tokens(text, normalization)
            for root in encoded_roots:
                text = text.replace(os.fsdecode(root), "<WORKSPACE>")
            return text.encode("ascii")
        lines = text.splitlines(keepends=True)
        if not lines or any(
            re.fullmatch(r"[a-z][a-z0-9_]*=.*\n?", line) is None
            for line in lines
        ):
            return content

        normalized = []
        object_labels: dict[str, str] = {}
        for line in lines:
            body = line.removesuffix("\n")
            key, value = body.split("=", 1)
            value = _replace_dynamic_tokens(value, normalization)
            for root in encoded_roots:
                value = value.replace(os.fsdecode(root), "<WORKSPACE>")
            if key in normalization.identity_fields and value not in {
                "absent",
                "none",
                "pending",
            }:
                value = _normalize_persisted_identity(
                    value,
                    object_labels,
                    dynamic_size=key in normalization.dynamic_identity_size_fields,
                    object_label=(
                        f"<FIELD-OBJECT:{key}>"
                        if key in normalization.field_scoped_identity_fields
                        else None
                    ),
                )
            elif key in normalization.dynamic_fields and value not in {
                "absent",
                "none",
                "pending",
            }:
                value = f"<DYNAMIC:{key}>"
            normalized.append(f"{key}={value}\n")
        return "".join(normalized).encode("ascii")

    return normalize


def _normalize_recovery_output(
    root: Path, value: str, normalization: _RecoveryNormalization
) -> str:
    return _replace_dynamic_tokens(
        value.replace(os.fspath(root), "<WORKSPACE>"), normalization
    )


def _read_transaction(root: Path, source: str) -> str:
    record = _read_strict_record(root / f"ns/pki/state/rollover/{source}")
    return record["transaction"]


def _recovery_argv(root: Path, tool: Path, action: str, source: str):
    transaction = _read_transaction(root, source)
    prefix: tuple[str | Path, ...]
    if tool == UNIFIED_PLATFORM_PKI:
        prefix = (tool, "ca-rollover", "recover")
    else:
        prefix = (tool, "recover")
    return (
        *prefix,
        "--namespace",
        root / "ns",
        "--transaction",
        transaction,
        "--action",
        action,
        "--yes",
    )


def _run_recovery_differential(
    seed: RolloverWorkspace,
    case_root: Path,
    action: str,
    prepare: Callable[[Path, Mapping[str, str]], None],
    environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
    normalization: _RecoveryNormalization,
    *,
    transaction_source: str = "journal",
) -> DifferentialResult:
    differential_environment = dict(environment)
    differential_environment["PLATFORM_TOOLS_LIB_DIR"] = os.fspath(
        FROZEN_BASH_LIBRARY
    )
    return run_differential_case(
        seed.root,
        case_root,
        Path("ns/pki"),
        lambda root: _recovery_argv(
            root, FROZEN_BASH_ROLLOVER, action, transaction_source
        ),
        lambda root: _recovery_argv(
            root, UNIFIED_PLATFORM_PKI, action, transaction_source
        ),
        differential_environment,
        output_normalizers=(
            lambda root, value: _normalize_recovery_output(
                root, value, normalization
            ),
        ),
        content_normalizers=(
            _recovery_content_normalizer(
                normalization,
                seed.root, case_root / "bash", case_root / "python"
            ),
        ),
        path_normalizers=(
            lambda value: _replace_dynamic_tokens(value, normalization),
        ),
        runner=process_runner,
        run_options={"timeout": 120},
        bash_prepare=prepare,
        python_prepare=prepare,
    )


def _require_process(result: ProcessResult, status: int, operation: str) -> None:
    assert result.status == status, f"{operation}: {result}"


def _rebase_seed_configs(workspace: RolloverWorkspace) -> None:
    for config in (
        workspace.pki / "authorities/roots/g1/openssl.cnf",
        workspace.pki / "authorities/intermediates/g1-i1/openssl.cnf",
    ):
        relative_directory = config.parent.relative_to(workspace.root)
        line = next(
            line
            for line in config.read_text(encoding="utf-8").splitlines()
            if line.startswith("dir = ")
        )
        old_directory = Path(line.removeprefix("dir = "))
        old_root = old_directory.parents[len(relative_directory.parts) - 1]
        assert old_root / relative_directory == old_directory
        if old_root != workspace.root:
            rebase_openssl_config(config, old_root, workspace.root)


def test_recovery_normalization_preserves_authenticated_evidence() -> None:
    normalize = _recovery_content_normalizer(_PREPARATION_NORMALIZATION)
    record = normalize(
        "state/rollover/journal",
        (
            "candidate_root_cert_identity=9:10:1000:644:1:765:regular file\n"
            "candidate_root_cert_pre_identity=9:10:1000:644:1:0:regular empty file\n"
            f"candidate_root_cert_sha256={'a' * 64}\n"
            f"candidate_intermediate_cert_sha256={'b' * 64}\n"
            "trust_bundle_sha256=none\n"
        ).encode("ascii"),
    ).decode("ascii")

    assert (
        "candidate_root_cert_identity=<OBJECT-1>:1000:644:1:765:regular file\n"
        in record
    )
    assert (
        "candidate_root_cert_pre_identity=<OBJECT-1>:1000:644:1:0:regular empty file\n"
        in record
    )
    assert f"candidate_root_cert_sha256={'a' * 64}\n" in record
    assert (
        "candidate_intermediate_cert_sha256="
        "<DYNAMIC:candidate_intermediate_cert_sha256>\n" in record
    )
    assert "trust_bundle_sha256=none\n" in record
    assert normalize("authorities/roots/g1/index.txt.old", b"stable\n") == b"stable\n"

    root_normalize = _recovery_content_normalizer(_ROOT_BOOTSTRAP_NORMALIZATION)
    root_record = root_normalize(
        "state/rollover/journal",
        (
            "reservation_reserved_identity=9:10:1000:600:1:65:regular file\n"
            "bootstrap_identity=9:10:1000:600:1:65:regular file\n"
        ).encode("ascii"),
    ).decode("ascii")
    assert (
        "reservation_reserved_identity="
        "<FIELD-OBJECT:reservation_reserved_identity>:1000:600:1:"
        "<DYNAMIC-SIZE>:regular file\n" in root_record
    )
    assert (
        "bootstrap_identity=<FIELD-OBJECT:bootstrap_identity>:"
        "1000:600:1:65:regular file\n" in root_record
    )
    assert _replace_dynamic_tokens(
        "authorities/intermediates/.platform-pki-intermediate-create.s-_D9Q",
        _INTERMEDIATE_BOOTSTRAP_NORMALIZATION,
    ) == "authorities/intermediates/<INTERMEDIATE-CREATE-STAGE>"

    intermediate_normalize = _recovery_content_normalizer(
        _INTERMEDIATE_BOOTSTRAP_NORMALIZATION
    )
    intermediate_record = intermediate_normalize(
        "state/rollover/journal",
        (
            "reservation_identity=9:10:1000:600:1:65:regular file\n"
            "root_index_pre_identity=9:10:1000:600:1:0:regular empty file\n"
            "root_newcert_post_identity=9:10:1000:644:1:765:regular file\n"
            "root_index_post_identity=11:12:1000:600:1:42:regular file\n"
        ).encode("ascii"),
    ).decode("ascii")
    assert (
        "reservation_identity=<OBJECT-1>:1000:600:1:"
        "<DYNAMIC-SIZE>:regular file\n" in intermediate_record
    )
    assert (
        "root_index_pre_identity=<FIELD-OBJECT:root_index_pre_identity>:"
        "1000:600:1:0:regular empty file\n" in intermediate_record
    )
    assert (
        "root_newcert_post_identity=<OBJECT-1>:1000:644:1:"
        "<DYNAMIC-SIZE>:regular file\n" in intermediate_record
    )
    assert (
        "root_index_post_identity=<OBJECT-2>:1000:600:1:42:regular file\n"
        in intermediate_record
    )

    manifest = _normalize_manifest(
        "state/rollovers/<INTERMEDIATE-PREPARATION>/"
        "candidate-intermediate-tree.manifest",
        (
            f"file|serial|11:12:1000:600:1:5:regular file|{'c' * 64}\n"
            "file|certs/intermediate-ca.crt|"
            f"13:14:1000:644:1:765:regular file|{'d' * 64}\n"
        ).encode("ascii"),
        _PREPARATION_NORMALIZATION,
    ).decode("ascii")

    assert (
        f"file|serial|<OBJECT-1>:1000:600:1:5:regular file|{'c' * 64}\n"
        in manifest
    )
    assert (
        "file|certs/intermediate-ca.crt|"
        "<OBJECT-2>:1000:644:1:<DYNAMIC-SIZE>:regular file|"
        "<GENERATED-SHA256:certs/intermediate-ca.crt>\n" in manifest
    )


def _create_backup(
    tools: RolloverTools,
    workspace: RolloverWorkspace,
    environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> Path:
    backup_directory = workspace.root / "differential-backups"
    backup_directory.mkdir(mode=0o700)
    result = process_runner(
        [
            *tools.backup,
            "--namespace",
            workspace.namespace,
            "--backup-dir",
            backup_directory,
            "--allow-plain-backup",
        ],
        env=environment,
        timeout=120,
    )
    _require_process(result, 0, "differential backup")
    receipts = tuple(backup_directory.glob("*.receipt"))
    assert len(receipts) == 1
    return receipts[0]


def test_recovery_differential_root_bootstrap_rollback(
    tmp_path: Path,
    rollover_tools: RolloverTools,
    rollover_workspace_factory: Callable[[str], RolloverWorkspace],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> None:
    seed = rollover_workspace_factory("differential-root-bootstrap-seed")
    initialized = process_runner(
        [*rollover_tools.init, "--namespace", seed.namespace],
        env=isolated_environment,
        timeout=120,
    )
    _require_process(initialized, 0, "root differential initialization")

    def interrupt(root: Path, environment: Mapping[str, str]) -> None:
        workspace = _copied_workspace(root)
        crashed = process_runner(
            [
                *rollover_tools.root,
                "--namespace",
                workspace.namespace,
                "--name",
                "Differential Root",
                "--org",
                "Test",
                "--country",
                "PL",
                "--allow-unencrypted-root-key",
            ],
            env=dict(environment, PLATFORM_PKI_ROOT_CRASH_AT="after-bootstrap"),
            timeout=120,
        )
        _require_process(crashed, 137, "root bootstrap interruption")

    _run_recovery_differential(
        seed,
        tmp_path / "differential-root-bootstrap",
        "rollback",
        interrupt,
        isolated_environment,
        process_runner,
        _ROOT_BOOTSTRAP_NORMALIZATION,
    ).assert_equivalent()


def test_recovery_differential_intermediate_cleanup_resume(
    tmp_path: Path,
    rollover_tools: RolloverTools,
    rollover_workspace_factory: Callable[[str], RolloverWorkspace],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> None:
    seed = rollover_workspace_factory("differential-intermediate-seed")
    for command, operation in (
        (
            [*rollover_tools.init, "--namespace", seed.namespace],
            "intermediate differential initialization",
        ),
        (
            [
                *rollover_tools.root,
                "--namespace",
                seed.namespace,
                "--name",
                "Differential Root",
                "--org",
                "Test",
                "--country",
                "PL",
                "--root-pass-file",
                seed.passphrase_file,
            ],
            "intermediate differential root",
        ),
    ):
        _require_process(
            process_runner(command, env=isolated_environment, timeout=120),
            0,
            operation,
        )

    # The writer retains terminal bootstrap evidence. It is not part of the
    # interrupted intermediate transaction copied into each differential case.
    journal = seed.pki / "state/rollover/journal"
    parsed = recovery_schema.parse_recovery_semantics(
        journal.read_bytes(), pki_dir=seed.pki
    )
    assert isinstance(parsed, recovery_schema.RootBootstrapRecoveryRecord)
    assert parsed.committed and parsed.phase == "complete"
    assert parsed.recovery_action is None and parsed.recovery_step is None
    journal_identity = identity_at(journal)
    assert isinstance(journal_identity, FileIdentity)
    with OpenedDirectory(journal.parent) as parent:
        unlink_exact(parent, journal.name, journal_identity)

    def interrupt(root: Path, environment: Mapping[str, str]) -> None:
        workspace = _copied_workspace(root)
        crashed = process_runner(
            [
                *rollover_tools.intermediate,
                "--namespace",
                workspace.namespace,
                "--name",
                "Differential Intermediate",
                "--org",
                "Test",
                "--country",
                "PL",
                "--root-pass-file",
                workspace.passphrase_file,
                "--allow-unencrypted-intermediate-key",
            ],
            env=dict(
                environment,
                PLATFORM_PKI_INTERMEDIATE_CRASH_AT="cleanup-pending",
            ),
            timeout=120,
        )
        _require_process(crashed, 137, "intermediate cleanup interruption")

    _run_recovery_differential(
        seed,
        tmp_path / "differential-intermediate-cleanup",
        "resume",
        interrupt,
        isolated_environment,
        process_runner,
        _INTERMEDIATE_BOOTSTRAP_NORMALIZATION,
    ).assert_equivalent()


@pytest.mark.parametrize("action", ("rollback", "resume"))
def test_recovery_differential_legacy_migration(
    tmp_path: Path,
    rollover_tools: RolloverTools,
    legacy_rollover_case_factory: Callable[[str], RolloverWorkspace],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
    action: str,
) -> None:
    seed = legacy_rollover_case_factory(f"differential-legacy-{action}-seed")

    def interrupt(root: Path, environment: Mapping[str, str]) -> None:
        workspace = _copied_workspace(root)
        receipt = _create_backup(
            rollover_tools, workspace, environment, process_runner
        )
        root_fingerprint = _certificate_fingerprint(
            workspace.pki / "root-ca/certs/root-ca.crt",
            environment,
            process_runner,
        )
        intermediate_fingerprint = _certificate_fingerprint(
            workspace.pki / "intermediate-ca/certs/intermediate-ca.crt",
            environment,
            process_runner,
        )
        crashed = process_runner(
            _migration_command(
                rollover_tools,
                workspace,
                receipt,
                root_fingerprint,
                intermediate_fingerprint,
            ),
            env=dict(
                environment,
                PLATFORM_PKI_MIGRATE_CRASH_AT="after-root-rename",
            ),
            timeout=120,
        )
        _require_process(crashed, 137, "legacy migration interruption")

    _run_recovery_differential(
        seed,
        tmp_path / f"differential-legacy-{action}",
        action,
        interrupt,
        isolated_environment,
        process_runner,
        _LEGACY_NORMALIZATION,
    ).assert_equivalent()


@pytest.mark.parametrize("action", ("rollback", "resume"))
def test_recovery_differential_preparation_root_db_window(
    tmp_path: Path,
    rollover_tools: RolloverTools,
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
    action: str,
) -> None:
    seed = rollover_case_factory(f"differential-preparation-{action}-seed")
    _rebase_seed_configs(seed)

    def interrupt(root: Path, environment: Mapping[str, str]) -> None:
        workspace = _copied_workspace(root)
        receipt = _create_backup(
            rollover_tools, workspace, environment, process_runner
        )
        key = "index"
        if action == "resume":
            selected, record, transaction_directory = _crash_after_staged(
                rollover_tools,
                workspace,
                receipt,
                environment,
                process_runner,
            )
            crash_point = f"resume-root-db-{key}-pending"
        else:
            selected = _crash_prepare(
                rollover_tools,
                workspace,
                receipt,
                "intermediate",
                2,
                "after-root-db",
                environment,
                process_runner,
                "publish-root-db-newcert-done",
            )
            record = _read_strict_record(
                workspace.pki / "state/rollover/journal"
            )
            transaction_directory = Path(record["transaction_dir"])
            crash_point = f"rollback-root-db-{key}-pending"

        crashed = process_runner(
            [
                FROZEN_BASH_ROLLOVER,
                "recover",
                "--namespace",
                workspace.namespace,
                "--transaction",
                selected["transaction"],
                "--action",
                action,
                "--yes",
            ],
            env=dict(environment, PLATFORM_PKI_RECOVER_CRASH_AT=crash_point),
            timeout=120,
        )
        _require_process(crashed, 137, f"{action} root DB interruption")

        destination = _root_db_destination(workspace, record, key)
        if action == "resume":
            source = _root_db_path(transaction_directory, record, key)
        else:
            relative = ROOT_DB_RELATIVES[key].format(
                issued_serial=record["issued_serial"]
            )
            source = transaction_directory / "stage/root-backup" / relative
        _replace_file_exact(source, destination)

    result = _run_recovery_differential(
        seed,
        tmp_path / f"differential-preparation-{action}",
        action,
        interrupt,
        isolated_environment,
        process_runner,
        _PREPARATION_NORMALIZATION,
    )
    # Final Bash rejects a successful publication whose identity was not yet
    # checkpointed; Python authenticates it from the pending step and consumed stage.
    assert result.bash.before == result.python.before
    assert result.bash.process.status == 1
    assert result.bash.process.stdout == ""
    assert result.bash.process.stderr == (
        "[ERROR] Root index is not in a journaled identity state\n"
    )
    assert result.python.process.status == 0
    assert result.python.process.stdout == (
        f"[OK] {'Resumed' if action == 'resume' else 'Rolled back'} preparation "
        "transaction: <INTERMEDIATE-PREPARATION>\n"
    )
    assert result.python.process.stderr == ""
    bash_after = {entry.path: entry for entry in result.bash.after}
    python_after = {entry.path: entry for entry in result.python.after}
    assert "state/rollover/journal" in bash_after
    assert "state/rollover/journal" not in python_after
    assert "state/rollover/terminal-<INTERMEDIATE-PREPARATION>" in python_after
    assert result.bash.after != result.python.after
    assert result.bash.transitions != result.python.transitions


def test_recovery_differential_terminal_marker_only_cleanup(
    tmp_path: Path,
    rollover_tools: RolloverTools,
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    isolated_environment: Mapping[str, str],
    process_runner: Callable[..., ProcessResult],
) -> None:
    seed = rollover_case_factory("differential-terminal-marker-seed")
    _rebase_seed_configs(seed)

    def interrupt(root: Path, environment: Mapping[str, str]) -> None:
        workspace = _copied_workspace(root)
        receipt = _create_backup(
            rollover_tools, workspace, environment, process_runner
        )
        journal = _crash_prepare(
            rollover_tools,
            workspace,
            receipt,
            "intermediate",
            2,
            "after-staged",
            environment,
            process_runner,
            "evidence-stage-done",
        )
        crashed = process_runner(
            [
                FROZEN_BASH_ROLLOVER,
                "recover",
                "--namespace",
                workspace.namespace,
                "--transaction",
                journal["transaction"],
                "--action",
                "resume",
                "--yes",
            ],
            env=dict(
                environment,
                PLATFORM_PKI_RECOVER_CRASH_AT="terminal-journal-done",
            ),
            timeout=120,
        )
        _require_process(crashed, 137, "terminal marker-only interruption")

    _run_recovery_differential(
        seed,
        tmp_path / "differential-terminal-marker",
        "resume",
        interrupt,
        isolated_environment,
        process_runner,
        _PREPARATION_NORMALIZATION,
        transaction_source="recovery-required",
    ).assert_equivalent()
