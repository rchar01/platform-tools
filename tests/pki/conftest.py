import os
import re
import shlex
import stat
from collections.abc import Callable, Generator, Mapping
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

import pytest

from src.platform_pki.ca_rollover_recovery import (
    MAX_RECOVERY_RECORD_BYTES,
    IntermediateBootstrapRecoveryRecord,
    RecoveryOperation,
    RecoveryRecordOrder,
    parse_recovery_semantics,
)
from src.platform_pki.filesystem import FilePolicy, FilesystemError, OpenedFile

from ..harness import ProcessResult, copy_tree, run_process


INVENTORY = """services:
  app:
    common_name: app.example.internal
    dns:
      - app.example.internal
  next:
    common_name: next.example.internal
    dns:
      - next.example.internal
  external:
    key_custody: host-local
    target: host-01
    validation_boundary_sha256: 0000000000000000000000000000000000000000000000000000000000000000
    rollback_hold_seconds: 3600
    common_name: external.example.internal
    dns:
      - external.example.internal
"""

TRANSACTION_ID = r"prepare-(?:root|intermediate)-[0-9]{8}-[0-9]{6}-[0-9]+"
BOOTSTRAP_ID = r"(?:root|intermediate)-bootstrap-[0-9]{8}-[0-9]{6}-[0-9]+"
PUBLIC_STATE_DIRECTORIES = (
    re.compile(r"state/generation-reservations"),
    re.compile(r"state/rollover"),
    re.compile(rf"state/rollover/{BOOTSTRAP_ID}"),
    re.compile(r"state/rollovers"),
    re.compile(rf"state/rollovers/{TRANSACTION_ID}"),
)
PUBLIC_STATE_FILES = (
    re.compile(r"state/(?:active-issuer|bootstrap-root|active-rollover)"),
    re.compile(r"state/generation-reservations/g[1-9][0-9]*(?:-i[1-9][0-9]*)?"),
    re.compile(r"state/rollover/(?:journal|recovery-required)"),
    re.compile(rf"state/rollover/terminal-{TRANSACTION_ID}"),
    re.compile(
        rf"state/rollover/{BOOTSTRAP_ID}/"
        r"(?:bootstrap-rollback|reservation-abandoned)"
    ),
    re.compile(
        rf"state/rollovers/{TRANSACTION_ID}/"
        r"(?:manifest|tree\.manifest|candidate-root-tree\.manifest|"
        r"candidate-intermediate-tree\.manifest|root-signing-stage-tree\.manifest)"
    ),
)
REDACTED_STATE_FILES = (
    re.compile(rf"state/rollovers/{TRANSACTION_ID}/trust-consumers\.yml"),
)
PYTHON_RECOVER_MODE = "PLATFORM_PKI_TEST_PYTHON_RECOVER"
ROLLOVER_WRAPPER = "PLATFORM_PKI_TEST_ROLLOVER_WRAPPER"


@dataclass(frozen=True)
class RolloverTools:
    init: Path
    root: Path
    intermediate: Path
    issue: Path
    backup: Path
    rollover: Path


@dataclass(frozen=True)
class RolloverWorkspace:
    root: Path
    namespace: Path
    pki: Path
    private_repo: Path
    passphrase_file: Path


def _write_private_text(path: Path, content: str) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(content)
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _isolated_environment(root: Path) -> Mapping[str, str]:
    home = root / "home"
    config = root / "config"
    temporary = root / "tmp"
    for directory in (home, config, temporary):
        directory.mkdir(mode=0o700, parents=True)
        directory.chmod(0o700)

    return {
        "HOME": os.fspath(home),
        "LC_ALL": "C",
        "NO_COLOR": "1",
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "TMPDIR": os.fspath(temporary),
        "XDG_CONFIG_HOME": os.fspath(config),
    }


def _workspace_paths(root: Path) -> RolloverWorkspace:
    return RolloverWorkspace(
        root=root,
        namespace=root / "ns",
        pki=root / "ns/pki",
        private_repo=root / "private",
        passphrase_file=root / "passphrase",
    )


def _workspace(root: Path) -> RolloverWorkspace:
    root.mkdir(mode=0o700, parents=True)
    root.chmod(0o700)
    workspace = _workspace_paths(root)
    workspace.private_repo.mkdir(mode=0o700)
    (workspace.private_repo / "pki").mkdir(mode=0o700)
    _write_private_text(
        workspace.passphrase_file, "pytest-rollover-passphrase\n"
    )
    return workspace


def _write_conditional_rollover_wrapper(
    wrapper: Path, unified_tool: Path, compatibility_tool: Path
) -> None:
    wrapper.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "if [[ ${1:-} == recover ]]; then\n"
        f"  exec {shlex.quote(os.fspath(unified_tool))} ca-rollover \"$@\"\n"
        "fi\n"
        f"exec {shlex.quote(os.fspath(compatibility_tool))} \"$@\"\n",
        encoding="ascii",
    )
    wrapper.chmod(0o755)


def _validate_case_name(name: str) -> None:
    if (
        not name
        or name in {".", ".."}
        or Path(name).is_absolute()
        or Path(name).parts != (name,)
    ):
        raise ValueError("rollover fixture name must be one relative path component")


def _checked_process(
    tools: RolloverTools,
    tool: Path,
    arguments: list[str | Path],
    environment: Mapping[str, str],
) -> ProcessResult:
    result = run_process(
        [tool, *arguments],
        env=environment,
        timeout=120,
    )
    if result.status != 0:
        name = next(
            field
            for field, value in tools.__dict__.items()
            if value == tool
        )
        pytest.fail(
            f"{name} fixture setup failed with status {result.status}: "
            f"stdout={result.stdout!r} stderr={result.stderr!r}"
        )
    return result


def _public_state_snapshot(workspace: RolloverWorkspace) -> tuple[str, ...]:
    state_root = workspace.pki / "state"
    if not state_root.exists():
        return ()

    entries = []
    for path in sorted(state_root.rglob("*")):
        relative = path.relative_to(workspace.pki).as_posix()
        if relative == "state/service" or relative.startswith("state/service/"):
            continue
        metadata = path.lstat()
        mode = stat.S_IMODE(metadata.st_mode)
        if stat.S_ISDIR(metadata.st_mode):
            if not any(pattern.fullmatch(relative) for pattern in PUBLIC_STATE_DIRECTORIES):
                raise ValueError(f"state snapshot path is not public: {relative}")
            detail = "directory"
        elif stat.S_ISREG(metadata.st_mode):
            if any(pattern.fullmatch(relative) for pattern in PUBLIC_STATE_FILES):
                detail = sha256(path.read_bytes()).hexdigest()
            elif any(
                pattern.fullmatch(relative) for pattern in REDACTED_STATE_FILES
            ):
                detail = f"redacted-size:{metadata.st_size}"
            else:
                raise ValueError(f"state snapshot path is not public: {relative}")
        else:
            raise ValueError(f"state snapshot object is not regular: {relative}")
        entries.append(f"{relative}\t{mode:o}\t{detail}")
    return tuple(entries)


@pytest.fixture
def rollover_tool(rollover_tools: RolloverTools) -> Path:
    return rollover_tools.rollover


@pytest.fixture
def isolated_environment(tmp_path: Path) -> Mapping[str, str]:
    return _isolated_environment(tmp_path / "environment")


@pytest.fixture(scope="session")
def _csr_workspace_seed(tmp_path_factory: pytest.TempPathFactory) -> Path:
    from .test_csr_signing import _create_csr_workspace

    root = tmp_path_factory.mktemp("pki-csr") / "seed"
    root.mkdir(mode=0o700)
    seed_environment = _isolated_environment(root / "environment")
    _create_csr_workspace(root, run_process, seed_environment)
    return root


def _authenticate_seed_intermediate_transaction(pki_dir: Path) -> str:
    reservation = pki_dir / "state/generation-reservations/g1-i1"
    data = b""
    try:
        with OpenedFile(
            os.fspath(reservation),
            policy=FilePolicy(
                owner=os.geteuid(),
                mode=0o600,
                links=1,
                max_size=4096,
            ),
        ) as opened:
            data = opened.read(opened.identity.size)
            opened.recheck()
    except FilesystemError:
        raise ValueError(
            f"CSR seed intermediate reservation is unsafe: {reservation}"
        ) from None
    match = re.fullmatch(
        rb"generation=g1-i1\n"
        rb"kind=intermediate\n"
        rb"status=consumed\n"
        rb"fingerprint_sha256=[0-9A-F]{64}\n"
        rb"transaction=(intermediate-bootstrap-[0-9]{8}-[0-9]{6}-[0-9]+)\n",
        data,
    )
    if match is None:
        raise ValueError(
            f"CSR seed intermediate reservation is not canonical: {reservation}"
        )
    return match.group(1).decode("ascii")


@pytest.fixture(scope="session")
def _csr_workspace_seed_transaction(_csr_workspace_seed: Path) -> str:
    return _authenticate_seed_intermediate_transaction(
        _csr_workspace_seed / "namespace/pki"
    )


def _validate_csr_seed_rollover_journal(
    data: bytes, pki_dir: Path, expected_transaction: str
) -> None:
    record = parse_recovery_semantics(data, pki_dir=pki_dir)
    if not (
        isinstance(record, IntermediateBootstrapRecoveryRecord)
        and record.operation is RecoveryOperation.INTERMEDIATE_BOOTSTRAP
        and record.schema == 3
        and record.order is RecoveryRecordOrder.WRITER
        and record.committed
        and record.phase == "complete"
        and record.recovery_action is None
        and record.recovery_step is None
        and record["transaction"] == expected_transaction
        and record.root_generation == "g1"
        and record.intermediate_generation == "g1-i1"
        and record.root_mutated
    ):
        raise ValueError(
            "CSR seed rollover journal is not the expected terminal intermediate bootstrap"
        )


def _authenticate_seed_rollover_journal(
    pki_dir: Path, expected_transaction: str
) -> bytes:
    journal = pki_dir / "state/rollover/journal"
    data = b""
    try:
        with OpenedFile(
            os.fspath(journal),
            policy=FilePolicy(
                owner=os.geteuid(),
                mode=0o600,
                links=1,
                max_size=MAX_RECOVERY_RECORD_BYTES,
            ),
        ) as opened:
            data = opened.read(opened.identity.size)
            opened.recheck()
    except FilesystemError:
        raise ValueError(f"CSR seed rollover journal is unsafe: {journal}") from None
    _validate_csr_seed_rollover_journal(data, pki_dir, expected_transaction)
    return data


def _copy_csr_seed_tree(
    source: Path, destination: Path, *, rebase_journal: bool
) -> None:
    from .migration_harness import rebase_openssl_config

    copy_tree(source, destination)
    for relative in (
        "namespace/pki/authorities/roots/g1/openssl.cnf",
        "namespace/pki/authorities/intermediates/g1-i1/openssl.cnf",
    ):
        rebase_openssl_config(destination / relative, source, destination)
    if rebase_journal:
        journal = destination / "namespace/pki/state/rollover/journal"
        data = journal.read_bytes()
        source_bytes = os.fsencode(source)
        if source_bytes not in data:
            raise ValueError("Copied CSR seed journal lacks its source path binding")
        rebased = data.replace(source_bytes, os.fsencode(destination))
        if source_bytes in rebased:
            raise ValueError("Copied CSR seed journal path rebasing is incomplete")
        journal.write_bytes(rebased)


@pytest.fixture
def csr_workspace_private_seed_copy(
    _csr_workspace_seed: Path,
) -> Callable[[Path], None]:
    def copy(destination: Path) -> None:
        _copy_csr_seed_tree(
            _csr_workspace_seed, destination, rebase_journal=True
        )

    return copy


@pytest.fixture
def csr_workspace_seed_copy(
    _csr_workspace_seed: Path,
    _csr_workspace_seed_transaction: str,
) -> Callable[..., None]:
    def copy(destination: Path, *, source: Path | None = None) -> None:
        source = _csr_workspace_seed if source is None else source
        source_journal = _authenticate_seed_rollover_journal(
            source / "namespace/pki", _csr_workspace_seed_transaction
        )
        _copy_csr_seed_tree(source, destination, rebase_journal=False)
        journal = destination / "namespace/pki/state/rollover/journal"
        journal_stat = journal.lstat()
        if not stat.S_ISREG(journal_stat.st_mode) or stat.S_ISLNK(
            journal_stat.st_mode
        ):
            raise ValueError(f"Copied terminal bootstrap journal is unsafe: {journal}")
        if journal.read_bytes() != source_journal:
            raise ValueError(f"Copied terminal bootstrap journal changed: {journal}")
        journal.unlink()

    return copy


@pytest.fixture(scope="session", autouse=True)
def _conditional_rollover_wrapper(
    tmp_path_factory: pytest.TempPathFactory,
) -> Generator[Path | None, None, None]:
    if not os.environ.get(PYTHON_RECOVER_MODE):
        yield None
        return

    repository = Path(__file__).resolve().parents[2]
    bin_dir = repository / "bin"
    wrapper_root = tmp_path_factory.mktemp("pki-rollover-wrapper")
    wrapper_bin = wrapper_root / "bin"
    wrapper_bin.mkdir(mode=0o700)
    (wrapper_root / "lib").symlink_to(repository / "lib", target_is_directory=True)
    wrapper = wrapper_bin / "platform-pki-ca-rollover"
    _write_conditional_rollover_wrapper(
        wrapper,
        bin_dir / "platform-pki",
        bin_dir / "platform-pki-ca-rollover",
    )
    previous = os.environ.get(ROLLOVER_WRAPPER)
    os.environ[ROLLOVER_WRAPPER] = os.fspath(wrapper)
    try:
        yield wrapper
    finally:
        if previous is None:
            os.environ.pop(ROLLOVER_WRAPPER, None)
        else:
            os.environ[ROLLOVER_WRAPPER] = previous


@pytest.fixture(scope="session")
def rollover_tools(_conditional_rollover_wrapper: Path | None) -> RolloverTools:
    bin_dir = Path(__file__).resolve().parents[2] / "bin"
    return RolloverTools(
        init=bin_dir / "platform-pki-init",
        root=bin_dir / "platform-pki-root-create",
        intermediate=bin_dir / "platform-pki-intermediate-create",
        issue=bin_dir / "platform-pki-service-issue",
        backup=bin_dir / "platform-pki-backup",
        rollover=(
            _conditional_rollover_wrapper
            or bin_dir / "platform-pki-ca-rollover"
        ),
    )


@pytest.fixture
def rollover_workspace_factory(
    tmp_path: Path,
) -> Callable[[str], RolloverWorkspace]:
    def create(name: str) -> RolloverWorkspace:
        _validate_case_name(name)
        return _workspace(tmp_path / "workspaces" / name)

    return create


@pytest.fixture
def rollover_control_workspace_factory(
    tmp_path: Path,
) -> Callable[[str], RolloverWorkspace]:
    def create(name: str) -> RolloverWorkspace:
        _validate_case_name(name)
        root = tmp_path / "control-workspaces" / name
        root.mkdir(mode=0o700, parents=True)
        root.chmod(0o700)
        return _workspace_paths(root)

    return create


@pytest.fixture(scope="session")
def _rollover_seed(
    tmp_path_factory: pytest.TempPathFactory,
    rollover_tools: RolloverTools,
) -> RolloverWorkspace:
    session_root = tmp_path_factory.mktemp("pki-rollover")
    environment = _isolated_environment(session_root / "environment")
    workspace = _workspace(session_root / "seed")

    _checked_process(
        rollover_tools,
        rollover_tools.init,
        ["--namespace", workspace.namespace],
        environment,
    )
    _write_private_text(workspace.pki / "inventory/services.yml", INVENTORY)
    _write_private_text(
        workspace.private_repo / "pki/services.yml", INVENTORY
    )
    _checked_process(
        rollover_tools,
        rollover_tools.root,
        [
            "--namespace",
            workspace.namespace,
            "--name",
            "Pytest Root",
            "--org",
            "Test",
            "--country",
            "PL",
            "--root-pass-file",
            workspace.passphrase_file,
        ],
        environment,
    )
    _checked_process(
        rollover_tools,
        rollover_tools.intermediate,
        [
            "--namespace",
            workspace.namespace,
            "--name",
            "Pytest Intermediate",
            "--org",
            "Test",
            "--country",
            "PL",
            "--root-pass-file",
            workspace.passphrase_file,
            "--intermediate-pass-file",
            workspace.passphrase_file,
        ],
        environment,
    )
    _checked_process(
        rollover_tools,
        rollover_tools.issue,
        [
            "app",
            "--namespace",
            workspace.namespace,
            "--intermediate-pass-file",
            workspace.passphrase_file,
        ],
        environment,
    )
    return workspace


@pytest.fixture
def rollover_case_factory(
    tmp_path: Path,
    _rollover_seed: RolloverWorkspace,
) -> Callable[[str], RolloverWorkspace]:
    def create(name: str) -> RolloverWorkspace:
        _validate_case_name(name)
        expected_transaction = _authenticate_seed_intermediate_transaction(
            _rollover_seed.pki
        )
        source_journal = _authenticate_seed_rollover_journal(
            _rollover_seed.pki, expected_transaction
        )
        destination = tmp_path / "cases" / name
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        copy_tree(_rollover_seed.root, destination)
        workspace = RolloverWorkspace(
            root=destination,
            namespace=destination / "ns",
            pki=destination / "ns/pki",
            private_repo=destination / "private",
            passphrase_file=destination / "passphrase",
        )
        journal = workspace.pki / "state/rollover/journal"
        journal_stat = journal.lstat()
        if not stat.S_ISREG(journal_stat.st_mode) or stat.S_ISLNK(
            journal_stat.st_mode
        ):
            raise ValueError(f"Copied terminal bootstrap journal is unsafe: {journal}")
        if journal.read_bytes() != source_journal:
            raise ValueError(f"Copied terminal bootstrap journal changed: {journal}")
        journal.unlink()
        return workspace

    return create


@pytest.fixture
def legacy_rollover_case_factory(
    rollover_case_factory: Callable[[str], RolloverWorkspace],
) -> Callable[[str], RolloverWorkspace]:
    def create(name: str) -> RolloverWorkspace:
        workspace = rollover_case_factory(name)
        generation_root = workspace.pki / "authorities/roots/g1"
        generation_intermediate = (
            workspace.pki / "authorities/intermediates/g1-i1"
        )
        legacy_root = workspace.pki / "root-ca"
        legacy_intermediate = workspace.pki / "intermediate-ca"
        generation_root.rename(legacy_root)
        generation_intermediate.rename(legacy_intermediate)

        for config, old_path, new_path in (
            (legacy_root / "openssl.cnf", generation_root, legacy_root),
            (
                legacy_intermediate / "openssl.cnf",
                generation_intermediate,
                legacy_intermediate,
            ),
        ):
            lines = config.read_text().splitlines(keepends=True)
            config.write_text(
                "".join(
                    f"dir = {new_path}\n"
                    if line.startswith("dir = ")
                    else line.replace(os.fspath(old_path), os.fspath(new_path))
                    for line in lines
                )
            )

        for path in (
            workspace.pki / "state/active-issuer",
            workspace.pki / "state/generation-reservations/g1",
            workspace.pki / "state/generation-reservations/g1-i1",
            workspace.pki / "services/app/issuer",
        ):
            path.unlink(missing_ok=True)
        return workspace

    return create


@pytest.fixture
def backup_receipt_factory(
    rollover_tools: RolloverTools,
    isolated_environment: Mapping[str, str],
) -> Callable[[RolloverWorkspace], Path]:
    def create(workspace: RolloverWorkspace) -> Path:
        backup_directory = workspace.root / "backups"
        backup_directory.mkdir(mode=0o700)
        _checked_process(
            rollover_tools,
            rollover_tools.backup,
            [
                "--namespace",
                workspace.namespace,
                "--backup-dir",
                backup_directory,
                "--allow-plain-backup",
            ],
            isolated_environment,
        )
        receipts = list(backup_directory.glob("*.receipt"))
        if len(receipts) != 1:
            pytest.fail(f"expected one backup receipt, found {receipts!r}")
        return receipts[0]

    return create


@pytest.fixture
def public_state_snapshot() -> Callable[[RolloverWorkspace], tuple[str, ...]]:
    return _public_state_snapshot


@pytest.fixture
def private_text_writer() -> Callable[[Path, str], None]:
    return _write_private_text
