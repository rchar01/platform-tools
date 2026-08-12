"""Install reviewed public CSR protocol trust as one protected directory."""

from __future__ import annotations

import os
import re
import secrets
import sys
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from typing import NoReturn

from .csr_history import CsrHistoryError, authenticate_retained_history
from .errors import ApplicationError
from .faults import DEFAULT_PAUSE_HOOK, FaultHook, PauseHook
from .filesystem import (
    ABSENT,
    DirectoryIdentity,
    DirectoryPolicy,
    FileIdentity,
    FilePolicy,
    FilesystemError,
    OpenedDirectory,
    open_trusted_directory,
)
from .operational import (
    acquire_operational_locks,
    prepare_control_state,
    require_no_unresolved_state,
    require_pki_directory,
    require_program,
    resolve_paths,
)
from .parser import ParseResult
from .paths import absolutize_path, expand_home, trees_are_disjoint
from .publication import (
    PublicationAmbiguousError,
    PublicationDestinationExistsError,
    PublicationError,
    TreeReadiness,
    fsync_tree,
    publish_no_clobber,
    remove_exact_tree,
    replace_exact,
    stage_file_bytes,
)
from .subprocesses import ProcessResult, run_process


_OWNER = os.geteuid()
_MAX_TRUST_BYTES = 65536
_SOURCE_FILE = FilePolicy(
    owner=_OWNER, forbidden_bits=0o022, links=1, max_size=_MAX_TRUST_BYTES
)
_INSTALLED_FILE = FilePolicy(
    owner=_OWNER, mode=0o600, links=1, max_size=_MAX_TRUST_BYTES
)
_PRIVATE_DIRECTORY = DirectoryPolicy(owner=_OWNER, mode=0o700)
_PRINCIPAL = re.compile(r"[a-z0-9][a-z0-9.-]*", re.ASCII)
_KEY = re.compile(r"[A-Za-z0-9+/]+={0,2}", re.ASCII)
_SCHEMA1_FILES = frozenset(
    (
        "approvers.allowed_signers",
        "policy",
        "requesters.allowed_signers",
        "responses.allowed_signers",
    )
)
_SCHEMA2_FILES = _SCHEMA1_FILES | {"deployers.allowed_signers"}
_SCHEMA1_POLICY = (
    "schema=1",
    "request_namespace=platform-pki-csr-request-v1",
    "approval_namespace=platform-pki-csr-approval-v1",
    "response_namespace=platform-pki-csr-response-v1",
    "request_max_age_seconds=604800",
    "sole_operator_min_delay_seconds=86400",
    "approval_max_age_seconds=86400",
    "clock_skew_seconds=300",
)
_SCHEMA2_POLICY = (
    "schema=2",
    "request_namespace=platform-pki-csr-request-v1",
    "approval_namespace=platform-pki-csr-approval-v1",
    "response_namespace=platform-pki-csr-response-v1",
    "deployment_namespace=platform-pki-csr-deployment-v1",
    "request_max_age_seconds=604800",
    "sole_operator_min_delay_seconds=86400",
    "approval_max_age_seconds=86400",
    "deployment_max_age_seconds=86400",
    "clock_skew_seconds=300",
)


def _die(message: str) -> NoReturn:
    raise ApplicationError(message)


@dataclass(frozen=True, slots=True)
class _TrustPolicy:
    schema: int
    files: frozenset[str]
    approver_principal: str
    response_principal: str


@dataclass(frozen=True, slots=True)
class _TrustFile:
    identity: FileIdentity
    data: bytes


@dataclass(frozen=True, slots=True)
class _TrustTree:
    path: str
    identity: DirectoryIdentity
    policy: _TrustPolicy
    files: Mapping[str, _TrustFile]
    installed: bool

    def recheck(self, environment: Mapping[str, str]) -> None:
        _load_trust_tree(
            self.path,
            environment,
            installed=self.installed,
            expected=self,
        )


def _text_lines(data: bytes, path: str) -> tuple[str, ...]:
    if (
        not data
        or len(data) > _MAX_TRUST_BYTES
        or not data.endswith(b"\n")
        or data.endswith(b"\n\n")
        or any(byte < 32 and byte != 10 or byte > 126 for byte in data)
    ):
        _die(
            "CSR trust source must be bounded ASCII text with one trailing "
            f"newline: {path}"
        )
    return tuple(line.decode("ascii") for line in data[:-1].split(b"\n"))


def _parse_policy(data: bytes, path: str) -> _TrustPolicy:
    lines = _text_lines(data, path)
    if lines[:1] == ("schema=1",):
        if len(lines) != 10:
            _die("CSR trust schema 1 policy must contain exactly 10 ordered fields")
        files = _SCHEMA1_FILES
    elif lines[:1] == ("schema=2",):
        if len(lines) != 12:
            _die("CSR trust schema 2 policy must contain exactly 12 ordered fields")
        files = _SCHEMA2_FILES
    else:
        _die("CSR trust policy schema must be 1 or 2")
    schema = 1 if files is _SCHEMA1_FILES else 2
    offset = 1 if schema == 2 else 0
    expected = (
        (1, "request_namespace=platform-pki-csr-request-v1", "CSR trust request namespace is invalid"),
        (2, "approval_namespace=platform-pki-csr-approval-v1", "CSR trust approval namespace is invalid"),
        (3, "response_namespace=platform-pki-csr-response-v1", "CSR trust response namespace is invalid"),
        (4 + offset, "request_max_age_seconds=604800", "CSR trust request maximum age must be 604800 seconds"),
        (5 + offset, "sole_operator_min_delay_seconds=86400", "CSR trust sole-operator delay must be 86400 seconds"),
        (6 + offset, "approval_max_age_seconds=86400", "CSR trust approval maximum age must be 86400 seconds"),
        (7 + 2 * offset, "clock_skew_seconds=300", "CSR trust clock skew must be 300 seconds"),
    )
    if schema == 2 and lines[4] != _SCHEMA2_POLICY[4]:
        _die("CSR trust deployment namespace is invalid")
    if schema == 2 and lines[8] != _SCHEMA2_POLICY[8]:
        _die("CSR trust deployment maximum age must be 86400 seconds")
    for index, value, message in expected:
        if lines[index] != value:
            _die(message)
    approver = re.fullmatch(
        r"approver_principal=([a-z0-9][a-z0-9.-]*)",
        lines[-2],
        re.ASCII,
    )
    response = re.fullmatch(
        r"response_principal=([a-z0-9][a-z0-9.-]*)",
        lines[-1],
        re.ASCII,
    )
    if approver is None:
        _die("CSR trust approver principal is invalid")
    if response is None:
        _die("CSR trust response principal is invalid")
    return _TrustPolicy(
        schema,
        files,
        approver.group(1),
        response.group(1),
    )


def _validate_public_key(
    key: str,
    environment: Mapping[str, str],
    label: str,
    pause_hook: PauseHook,
) -> None:
    temporary = tempfile.mkdtemp(prefix="platform-pki-csr-public-key.")
    try:
        os.chmod(temporary, 0o700)
        with OpenedDirectory(temporary, policy=_PRIVATE_DIRECTORY) as parent:
            with stage_file_bytes(
                parent,
                "public-key",
                f"ssh-ed25519 {key}\n".encode("ascii"),
            ) as staged:
                pause_hook("csr-trust-public-key-before-validation")
                result = run_process(
                    (
                        "ssh-keygen",
                        "-l",
                        "-f",
                        f"/proc/self/fd/{staged.fileno()}",
                    ),
                    env=environment,
                    pass_fds=(staged.fileno(),),
                    timeout=30.0,
                    term_grace=1.0,
                    stdout_limit=1024 * 1024,
                    stderr_limit=1024 * 1024,
                )
                if not isinstance(result, ProcessResult) or result.status:
                    _die(f"{label} contains an invalid Ed25519 public key")
    except (FilesystemError, PublicationError):
        _die("Cannot stage CSR trust public-key validation")
    finally:
        try:
            os.rmdir(temporary)
        except OSError:
            pass


def _validate_allowed_signers(
    data: bytes,
    path: str,
    label: str,
    environment: Mapping[str, str],
    pause_hook: PauseHook,
    *,
    required: str | None = None,
) -> None:
    lines = _text_lines(data, path)
    seen: set[str] = set()
    for line in lines:
        fields = line.split(" ")
        if (
            len(fields) != 3
            or _PRINCIPAL.fullmatch(fields[0]) is None
            or fields[1] != "ssh-ed25519"
            or _KEY.fullmatch(fields[2]) is None
        ):
            _die(f"{label} must contain only no-options Ed25519 allowed-signer records")
        if fields[0] in seen:
            _die(f"{label} contains duplicate principal: {fields[0]}")
        seen.add(fields[0])
        _validate_public_key(fields[2], environment, label, pause_hook)
    if not seen:
        _die(f"{label} must contain at least one signer")
    if required is not None and required not in seen:
        _die(f"{label} does not contain required principal: {required}")
    if required is not None and len(seen) != 1:
        _die(f"{label} must contain exactly the pinned principal: {required}")


def _read_trust_file(
    directory: OpenedDirectory,
    name: str,
    path: str,
    *,
    installed: bool,
) -> _TrustFile:
    try:
        with directory.open_file(
            name, policy=_INSTALLED_FILE if installed else _SOURCE_FILE
        ) as opened:
            data = opened.read(_MAX_TRUST_BYTES)
            return _TrustFile(opened.recheck(), data)
    except FilesystemError:
        if installed:
            _die(f"Installed CSR trust file is unsafe: {path}/{name}")
        _die(
            "CSR trust source must be a readable non-symlink regular file: "
            f"{path}/{name}"
        )
    raise AssertionError("unreachable")


def _load_trust_tree(
    path: str,
    environment: Mapping[str, str],
    *,
    installed: bool,
    expected: _TrustTree | None = None,
    pause_hook: PauseHook = DEFAULT_PAUSE_HOOK,
) -> _TrustTree:
    label = "Installed CSR trust" if installed else "CSR trust source"
    files: dict[str, _TrustFile] = {}
    identity: DirectoryIdentity | None = None
    policy: _TrustPolicy | None = None
    try:
        directory = (
            OpenedDirectory(
                path,
                policy=_PRIVATE_DIRECTORY,
                expected_identity=expected.identity if expected is not None else None,
            )
            if installed
            else open_trusted_directory(path)
        )
        with directory:
            if expected is not None and directory.directory_identity != expected.identity:
                _die(f"{label} changed during installation")
            names = frozenset(os.listdir(directory.fileno()))
            if "policy" not in names:
                _die("CSR trust directory has an invalid file set")
            policy_input = _read_trust_file(
                directory, "policy", path, installed=installed
            )
            policy = _parse_policy(policy_input.data, f"{path}/policy")
            if names != policy.files:
                _die(
                    "CSR trust directory must contain exactly policy and the "
                    "allowed_signers files required by its policy schema"
                )
            files = {"policy": policy_input}
            for name in sorted(policy.files - {"policy"}):
                item = _read_trust_file(
                    directory, name, path, installed=installed
                )
                _text_lines(item.data, f"{path}/{name}")
                files[name] = item
            identity = directory.recheck().directory
    except FilesystemError:
        _die(f"{label} directory or file is unsafe: {path}")
    assert identity is not None and policy is not None
    _validate_allowed_signers(
        files["requesters.allowed_signers"].data,
        f"{path}/requesters.allowed_signers",
        "CSR requester trust",
        environment,
        pause_hook,
    )
    _validate_allowed_signers(
        files["approvers.allowed_signers"].data,
        f"{path}/approvers.allowed_signers",
        "CSR approver trust",
        environment,
        pause_hook,
        required=policy.approver_principal,
    )
    _validate_allowed_signers(
        files["responses.allowed_signers"].data,
        f"{path}/responses.allowed_signers",
        "CSR response trust",
        environment,
        pause_hook,
        required=policy.response_principal,
    )
    if policy.schema == 2:
        _validate_allowed_signers(
            files["deployers.allowed_signers"].data,
            f"{path}/deployers.allowed_signers",
            "CSR deployer trust",
            environment,
            pause_hook,
        )
    result = _TrustTree(path, identity, policy, files, installed)
    if expected is not None and result != expected:
        _die(f"{label} changed during installation")
    return result


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    try:
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("write made no progress")
            view = view[written:]
    finally:
        view.release()


def _create_stage(
    parent: OpenedDirectory, source: _TrustTree
) -> tuple[str, OpenedDirectory]:
    for _attempt in range(16):
        name = f".platform-pki-csr-trust.{secrets.token_hex(16)}"
        try:
            os.mkdir(name, 0o700, dir_fd=parent.fileno())
        except FileExistsError:
            continue
        except OSError:
            _die("Cannot create CSR trust staging directory")
        break
    else:
        _die("Cannot create CSR trust staging directory")
    stage: OpenedDirectory | None = None
    try:
        stage = parent.open_directory(name, policy=_PRIVATE_DIRECTORY)
        for file_name in sorted(source.policy.files):
            descriptor = os.open(
                file_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
                dir_fd=stage.fileno(),
            )
            try:
                os.fchmod(descriptor, 0o600)
                _write_all(descriptor, source.files[file_name].data)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        stage.recheck()
        stage.close()
        stage = parent.open_directory(name, policy=_PRIVATE_DIRECTORY)
        return name, stage
    except (OSError, FilesystemError):
        if stage is not None:
            stage.close()
        try:
            partial = parent.open_directory(name, policy=_PRIVATE_DIRECTORY)
            try:
                partial_identity = partial.recheck()
                partial_readiness = fsync_tree(partial, parent, name)
            finally:
                partial.close()
            remove_exact_tree(
                parent,
                name,
                partial_identity,
                partial_readiness,
            )
        except (FilesystemError, PublicationError):
            _retained_warning(parent, name)
        _die("Cannot stage CSR trust files")


def _same(first: _TrustTree, second: _TrustTree) -> bool:
    return first.policy.schema == second.policy.schema and all(
        first.files[name].data == second.files[name].data
        for name in first.policy.files
    )


def _retained_warning(parent: OpenedDirectory, name: str) -> None:
    root = os.path.realpath(f"/proc/self/fd/{parent.fileno()}")
    print(
        f"[WARN] CSR trust publication requires inspection; retained evidence: {root}/{name}",
        file=sys.stderr,
        flush=True,
    )


def _ambiguous_initial_publication_warning(
    parent: OpenedDirectory, stage_name: str
) -> None:
    root = os.path.realpath(f"/proc/self/fd/{parent.fileno()}")
    print(
        "[WARN] CSR trust publication requires inspection; retained evidence may be at: "
        f"{root}/csr-trust or {root}/{stage_name}",
        file=sys.stderr,
        flush=True,
    )


def _install_locked(
    pki_dir: str,
    source: _TrustTree,
    inventory: OpenedDirectory,
    environment: Mapping[str, str],
    fault_hook: FaultHook,
    pause_hook: PauseHook,
) -> int:
    stage_name: str | None = None
    stage_identity: FileIdentity | None = None
    stage_readiness: TreeReadiness | None = None
    preserve = False
    ambiguity_reported = False
    stage: OpenedDirectory | None = None
    installed_tree: _TrustTree | None = None
    installed_directory: OpenedDirectory | None = None
    try:
        source.recheck(environment)
        stage_name, stage = _create_stage(inventory, source)
        stage_identity = stage.recheck()
        stage_readiness = fsync_tree(stage, inventory, stage_name)
        pause_hook("csr-trust-after-stage-before-source-recheck")
        source.recheck(environment)
        staged_tree = _load_trust_tree(
            f"{pki_dir}/inventory/{stage_name}", environment, installed=True
        )

        destination_identity = inventory.identity_at("csr-trust")
        if destination_identity is not ABSENT:
            if not isinstance(destination_identity, FileIdentity) or destination_identity.kind != "directory":
                _die("Installed CSR trust directory is unsafe")
            installed_directory = inventory.open_directory(
                "csr-trust",
                policy=_PRIVATE_DIRECTORY,
                expected_identity=destination_identity,
            )
            installed_tree = _load_trust_tree(
                f"{pki_dir}/inventory/csr-trust", environment, installed=True
            )
            if _same(staged_tree, installed_tree):
                source.recheck(environment)
                staged_tree.recheck(environment)
                pause_hook("csr-trust-before-noop-installed-recheck")
                installed_tree.recheck(environment)
                stage.close()
                stage = None
                remove_exact_tree(
                    inventory,
                    stage_name,
                    stage_identity,
                    stage_readiness,
                )
                stage_name = None
                print(
                    f"[OK] CSR trust already current: {pki_dir}/inventory/csr-trust",
                    flush=True,
                )
                return 0

        history = None
        installed_schema = (
            installed_tree.policy.schema if installed_tree is not None else None
        )
        if staged_tree.policy.schema == 2 or installed_schema == 2:
            try:
                history = authenticate_retained_history(pki_dir, environment)
            except CsrHistoryError as error:
                _die(str(error))
            source.recheck(environment)

        def final_authorization() -> None:
            source.recheck(environment)
            staged_tree.recheck(environment)
            if installed_tree is not None:
                installed_tree.recheck(environment)
            if history is not None:
                history()

        final_authorization()
        if installed_tree is None:
            try:
                publish_no_clobber(
                    inventory,
                    stage_name,
                    stage_identity,
                    inventory,
                    "csr-trust",
                    readiness=stage_readiness,
                    pre_publish_check=final_authorization,
                    fault_hook=fault_hook,
                    pause_hook=pause_hook,
                )
            except PublicationDestinationExistsError:
                _die("CSR trust destination appeared before publication")
            except PublicationAmbiguousError:
                preserve = True
                ambiguity_reported = True
                _ambiguous_initial_publication_warning(inventory, stage_name)
                _die("Published CSR trust identity is ambiguous")
            stage_name = None
            status = "installed"
        else:
            assert isinstance(destination_identity, FileIdentity)
            assert installed_directory is not None
            destination_readiness = fsync_tree(
                installed_directory, inventory, "csr-trust"
            )
            try:
                result = replace_exact(
                    inventory,
                    stage_name,
                    stage_identity,
                    inventory,
                    "csr-trust",
                    destination_identity,
                    source_readiness=stage_readiness,
                    destination_readiness=destination_readiness,
                    pre_exchange_check=final_authorization,
                    fault_hook=fault_hook,
                    pause_hook=pause_hook,
                )
            except PublicationAmbiguousError:
                preserve = True
                _die("CSR trust exchange requires inspection")
            stage_identity = result.old_destination_identity
            stage_readiness = result.old_destination_readiness
            assert stage_readiness is not None
            if stage is not None:
                stage.close()
                stage = None
            if installed_directory is not None:
                installed_directory.close()
                installed_directory = None
            try:
                remove_exact_tree(
                    inventory,
                    stage_name,
                    stage_identity,
                    stage_readiness,
                    fault_hook=fault_hook,
                    pause_hook=pause_hook,
                )
            except PublicationError:
                preserve = True
                _die("Cannot remove prior CSR trust after publication")
            stage_name = None
            status = "updated"
        print(
            f"[OK] CSR trust {status}: {pki_dir}/inventory/csr-trust",
            flush=True,
        )
        return 0
    except PublicationError as error:
        _die(str(error))
    finally:
        if installed_directory is not None:
            installed_directory.close()
        if stage is not None:
            stage.close()
        if stage_name is not None and stage_identity is not None:
            if preserve or stage_readiness is None:
                if not ambiguity_reported:
                    _retained_warning(inventory, stage_name)
            else:
                try:
                    remove_exact_tree(
                        inventory,
                        stage_name,
                        stage_identity,
                        stage_readiness,
                        fault_hook=fault_hook,
                        pause_hook=pause_hook,
                    )
                except PublicationError:
                    _retained_warning(inventory, stage_name)
    raise AssertionError("unreachable")


def install_csr_trust(parsed: ParseResult) -> int:
    """Run the parsed ``csr-trust-install`` route."""

    environment = dict(os.environ)
    os.umask(0o077)
    require_program("ssh-keygen", environment)
    require_program("openssl", environment)
    fault = FaultHook(
        failure_at=environment.get("PLATFORM_PKI_CSR_TRUST_INSTALL_FAILURE_AT")
    )
    pause = PauseHook(
        pause_at=environment.get("PLATFORM_PKI_CSR_TRUST_INSTALL_PAUSE_AT"),
        marker=environment.get("PLATFORM_PKI_CSR_TRUST_INSTALL_PAUSE_MARKER"),
        release=environment.get("PLATFORM_PKI_CSR_TRUST_INSTALL_PAUSE_RELEASE"),
    )
    paths = resolve_paths(parsed.values, environment)
    private_value = expand_home(parsed["--private-repo"], home=environment.get("HOME", ""))
    private_real: str | None = None
    try:
        physical_cwd = os.getcwd()
    except OSError:
        _die("Cannot resolve physical current directory")
    private_path = absolutize_path(
        os.path.normpath(os.path.join(physical_cwd, private_value)),
        physical_cwd=physical_cwd,
    )
    try:
        with open_trusted_directory(private_path) as private_directory:
            private_real = os.path.realpath(
                f"/proc/self/fd/{private_directory.fileno()}"
            )
        source_path = f"{private_real}/pki/csr-trust"
        with open_trusted_directory(source_path):
            pass
    except FilesystemError:
        _die(f"CSR trust source directory is missing or unsafe: {private_path}/pki/csr-trust")
    assert private_real is not None
    source = _load_trust_tree(
        source_path,
        environment,
        installed=False,
        pause_hook=pause,
    )

    require_pki_directory(paths.pki_dir)
    prepare_control_state(paths.pki_dir)
    pki_real: str | None = None
    try:
        with OpenedDirectory(
            paths.pki_dir, policy=_PRIVATE_DIRECTORY
        ) as pki_directory:
            pki_real = os.path.realpath(f"/proc/self/fd/{pki_directory.fileno()}")
    except FilesystemError:
        _die("PKI directory does not satisfy its private path policy")
    assert pki_real is not None
    if not trees_are_disjoint(private_real, pki_real):
        _die("Private repository and PKI destination trees must be disjoint")

    with acquire_operational_locks(pki_real, "inventory"):
        require_no_unresolved_state(pki_real)
        try:
            with OpenedDirectory(
                f"{pki_real}/inventory",
                policy=DirectoryPolicy(owner=_OWNER, forbidden_bits=0o022),
            ) as inventory:
                return _install_locked(
                    pki_real,
                    source,
                    inventory,
                    environment,
                    fault,
                    pause,
                )
        except FilesystemError:
            _die("Inventory directory is unsafe")
    raise AssertionError("unreachable")
