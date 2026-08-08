"""Publish managed service material as one durable Ansible export tree."""

from __future__ import annotations

import os
import re
import secrets
import stat
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn

from .errors import ApplicationError
from .faults import FaultHook, PauseHook
from .filesystem import (
    ABSENT,
    DirectoryPolicy,
    FileIdentity,
    FilePolicy,
    FilesystemError,
    OpenedDirectory,
    OpenedFile,
    identity_from_stat,
)
from .inventory import Inventory, InventoryError, InventoryService, parse_inventory
from .operational import (
    acquire_operational_locks,
    prepare_control_state,
    require_generation_layout,
    require_inventory_readable,
    require_pilot_common_library,
    require_pki_directory,
    require_program,
    run_external,
    validate_service_name,
)
from .parser import ParseResult
from .publication import (
    PublicationAmbiguousError,
    PublicationDestinationExistsError,
    PublicationError,
    TreeReadiness,
    fsync_tree,
    publish_no_clobber,
    remove_exact_tree,
    replace_exact,
)


_ROOT_GENERATION = re.compile(r"g[1-9][0-9]*", re.ASCII)
_INTERMEDIATE_GENERATION = re.compile(r"g[1-9][0-9]*-i[1-9][0-9]*", re.ASCII)
_MARKER_NAME = ".platform-pki-ansible-export"
_MARKER_BYTES = b"platform-pki-export-ansible\n"
_STAGE_ATTEMPTS = 16
_WRITE_CHUNK = 64 * 1024


def _die(message: str) -> NoReturn:
    raise ApplicationError(message)


def _warn(message: str) -> None:
    print(f"[WARN] {message}", file=sys.stderr, flush=True)


def _ok(message: str) -> None:
    print(f"[OK] {message}", flush=True)


def _expand_path(path: str, environment: Mapping[str, str]) -> str:
    if path == "~":
        return environment.get("HOME", "")
    if path.startswith("~/"):
        return f"{environment.get('HOME', '')}/{path[2:]}"
    return path


def _default_namespace(environment: Mapping[str, str]) -> str:
    base = environment.get("XDG_CONFIG_HOME") or f"{environment.get('HOME', '')}/.config"
    return f"{base}/platform-infrastructure"


def _absolute_pki(path: str) -> str:
    if path.startswith("/"):
        return path
    try:
        return f"{os.getcwd()}/{path}"
    except OSError:
        _die("Current directory could not be resolved")


def _components(path: str):
    current = ""
    for component in path.split("/"):
        if not component or component == ".":
            continue
        current = f"/{component}" if not current else f"{current}/{component}"
        yield current


def _require_trusted_components(path: str, label: str) -> None:
    uid = os.geteuid()
    for current in _components(path):
        try:
            result = os.lstat(current)
        except FileNotFoundError:
            continue
        except OSError:
            _die(f"Cannot inspect {label} path component: {current}")
        if stat.S_ISLNK(result.st_mode):
            _die(f"{label} path component must not be a symlink: {current}")
        if not stat.S_ISDIR(result.st_mode):
            _die(f"{label} path component is not a directory: {current}")
        permissions = stat.S_IMODE(result.st_mode)
        if permissions & 0o022 and not permissions & stat.S_ISVTX:
            _die(
                f"{label} path component is group- or world-writable without sticky bit: {current}"
            )
        if result.st_uid not in (uid, 0):
            _die(f"{label} path component is not owned by current user or root: {current}")


def _require_private_directory(path: str, label: str) -> FileIdentity:
    try:
        result = os.lstat(path)
        identity = identity_from_stat(result)
    except (OSError, FilesystemError):
        _die(f"{label} directory is missing: {path}")
    if identity.kind != "directory":
        _die(f"{label} directory is missing: {path}")
    if identity.uid != os.geteuid():
        _die(f"{label} directory is not owned by the current user: {path}")
    if identity.permissions & 0o022:
        _die(f"{label} directory is group- or world-writable: {path}")
    return identity


def _pair(data: bytes, label: str, path: str) -> tuple[str, str]:
    message = f"{label} manifest has invalid content: {path}"
    if data.endswith(b"\n"):
        data = data[:-1]
    lines = data.split(b"\n")
    if (
        len(lines) != 2
        or not lines[0].startswith(b"root=")
        or not lines[1].startswith(b"intermediate=")
    ):
        _die(message)
    try:
        root = lines[0][5:].decode("ascii")
        intermediate = lines[1][13:].decode("ascii")
    except UnicodeDecodeError:
        _die(message)
    if (
        _ROOT_GENERATION.fullmatch(root) is None
        or _INTERMEDIATE_GENERATION.fullmatch(intermediate) is None
        or not intermediate.startswith(f"{root}-i")
    ):
        _die(message)
    return root, intermediate


@dataclass(slots=True)
class _Source:
    path: str
    opened: OpenedFile
    data: bytes
    bulk_recheck: bool = True


class _Sources:
    def __init__(self) -> None:
        self.items: list[_Source] = []

    def open(
        self,
        path: str,
        *,
        policy: FilePolicy | None = None,
        label: str | None = None,
    ) -> _Source:
        opened: OpenedFile | None = None
        try:
            opened = OpenedFile(path, policy=policy)
            data = opened.read(opened.identity.size)
        except FilesystemError:
            if opened is not None:
                try:
                    opened.close()
                except FilesystemError:
                    pass
            _die(label or f"Required file is missing: {path}")
        source = _Source(path, opened, data)
        self.items.append(source)
        return source

    def open_at(
        self,
        parent: OpenedDirectory,
        name: str,
        path: str,
        *,
        policy: FilePolicy,
        label: str,
        bulk_recheck: bool = True,
    ) -> _Source:
        opened: OpenedFile | None = None
        try:
            opened = parent.open_file(name, policy=policy)
            data = opened.read(opened.identity.size)
        except FilesystemError:
            if opened is not None:
                try:
                    opened.close()
                except FilesystemError:
                    pass
            _die(label)
        source = _Source(path, opened, data, bulk_recheck)
        self.items.append(source)
        return source

    def recheck(self) -> None:
        try:
            for source in self.items:
                if source.bulk_recheck:
                    source.opened.recheck()
        except FilesystemError:
            _die("Export source identity changed before publication")

    def close(self) -> None:
        for source in reversed(self.items):
            try:
                source.opened.close()
            except FilesystemError:
                pass
        self.items.clear()


def _inventory_service(inventory: Inventory, name: str, path: str) -> InventoryService:
    for service in inventory.services:
        if service.name == name:
            return service
    _die(f"Service is not defined in {path}: {name}")


def _service_paths(pki_dir: str, service: str) -> tuple[str, ...]:
    root = f"{pki_dir}/services/{service}"
    return (
        f"{root}/certs/tls.crt",
        f"{root}/private/tls.key",
        f"{root}/chain/ca-chain.crt",
        f"{root}/chain/fullchain.crt",
        f"{root}/issuer",
    )


def _service_generated(pki_dir: str, service: str) -> bool:
    return all(os.path.isfile(path) for path in _service_paths(pki_dir, service))


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    offset = 0
    try:
        while offset < len(view):
            written = os.write(descriptor, view[offset : offset + _WRITE_CHUNK])
            if written <= 0:
                raise OSError("write made no progress")
            offset += written
    finally:
        view.release()


def _make_directory(parent: OpenedDirectory, name: str) -> OpenedDirectory:
    try:
        os.mkdir(name, 0o700, dir_fd=parent.fileno())
        child = parent.open_directory(
            name, policy=DirectoryPolicy(owner=os.geteuid(), mode=0o700)
        )
    except (OSError, FilesystemError):
        _die(f"Export path unexpectedly exists: {name}")
    return child


def _write_file(parent: OpenedDirectory, name: str, data: bytes, mode: int) -> None:
    descriptor = -1
    try:
        descriptor = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            mode,
            dir_fd=parent.fileno(),
        )
        os.fchmod(descriptor, mode)
        _write_all(descriptor, data)
        os.fsync(descriptor)
        identity = identity_from_stat(os.fstat(descriptor))
        FilePolicy(owner=os.geteuid(), mode=mode, links=1).validate(identity)
        if identity.size != len(data) or parent.identity_at(name) != identity:
            raise OSError("staged identity mismatch")
    except (OSError, FilesystemError):
        _die(f"Failed to stage export file: {name}")
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _reserve_stage(parent: OpenedDirectory, destination: str) -> tuple[str, OpenedDirectory]:
    for _attempt in range(_STAGE_ATTEMPTS):
        name = f".{destination}.recovery-{secrets.token_hex(16)}"
        try:
            os.mkdir(name, 0o700, dir_fd=parent.fileno())
        except FileExistsError:
            continue
        except OSError:
            _die("Cannot create same-parent Ansible export staging directory")
        try:
            return name, parent.open_directory(
                name, policy=DirectoryPolicy(owner=os.geteuid(), mode=0o700)
            )
        except FilesystemError:
            _warn(
                "Ansible export staging evidence retained because its exact identity "
                f"could not be opened: {_recovery_path(parent, name)}"
            )
            _die("Cannot validate same-parent Ansible export staging directory")
    _die("Cannot reserve same-parent Ansible export staging directory")


def _recheck_marker(marker: _Source, export_real: str) -> None:
    try:
        marker.opened.recheck()
        data = marker.opened.read(marker.opened.identity.size)
        marker.opened.recheck()
    except FilesystemError:
        _die(f"Custom export authorization marker changed before publication: {export_real}")
    if data != _MARKER_BYTES:
        _die(f"Custom export authorization marker changed before publication: {export_real}")


def _recovery_path(parent: OpenedDirectory, name: str) -> str:
    return f"{os.path.realpath(f'/proc/self/fd/{parent.fileno()}')}/{name}"


def _authorize_destination(
    parent: OpenedDirectory,
    name: str,
    export_real: str,
    default_real: str,
    sources: _Sources,
) -> tuple[FileIdentity | object, OpenedDirectory | None, _Source | None]:
    try:
        identity = parent.identity_at(name)
    except FilesystemError:
        _die(f"Export directory must not be a symlink: {export_real}")
    if identity is ABSENT:
        return ABSENT, None, None
    assert isinstance(identity, FileIdentity)
    if identity.kind != "directory":
        _die(f"Export directory is missing: {export_real}")
    try:
        opened = parent.open_directory(
            name,
            policy=DirectoryPolicy(owner=os.geteuid(), mode=0o700),
            expected_identity=identity,
        )
    except FilesystemError:
        _die(f"Export directory does not satisfy its private path policy: {export_real}")
    if export_real != default_real:
        marker = sources.open_at(
            opened,
            _MARKER_NAME,
            f"{export_real}/{_MARKER_NAME}",
            policy=FilePolicy(
                owner=os.geteuid(), mode=0o600, links=1, max_size=len(_MARKER_BYTES)
            ),
            label=f"Refusing to replace unmarked custom export directory: {export_real}",
            bulk_recheck=False,
        )
        if marker.data != _MARKER_BYTES:
            opened.close()
            _die(f"Refusing to replace unmarked custom export directory: {export_real}")
        return identity, opened, marker
    return identity, opened, None


def _build_stage(
    stage: OpenedDirectory,
    root_certificate: bytes,
    service_data: tuple[tuple[str, tuple[bytes, bytes, bytes, bytes]], ...],
) -> None:
    _write_file(stage, _MARKER_NAME, _MARKER_BYTES, 0o600)
    ca = _make_directory(stage, "ca")
    services = _make_directory(stage, "services")
    try:
        _write_file(ca, "root-ca.crt", root_certificate, 0o644)
        for service, files in service_data:
            target = _make_directory(services, service)
            try:
                for name, data, mode in zip(
                    ("tls.crt", "tls.key", "ca-chain.crt", "fullchain.crt"),
                    files,
                    (0o644, 0o600, 0o644, 0o644),
                    strict=True,
                ):
                    _write_file(target, name, data, mode)
            finally:
                target.close()
    finally:
        services.close()
        ca.close()


def export_ansible(parsed: ParseResult) -> int:
    """Run the compatibility and unified Ansible export workflow."""

    environment = dict(os.environ)
    require_pilot_common_library(environment)
    require_program("openssl", environment)
    services = tuple(parsed["services"])
    for service in services:
        validate_service_name(service)

    namespace_value = parsed.values.get("--namespace")
    namespace = _expand_path(
        str(namespace_value) if namespace_value is not None else _default_namespace(environment),
        environment,
    )
    pki_value = parsed.values.get("--pki-dir")
    pki_dir = _absolute_pki(
        _expand_path(str(pki_value), environment)
        if pki_value is not None
        else f"{namespace}/pki"
    )
    export_value = parsed.values.get("--export-dir")
    export_provided = "--export-dir" in parsed.provided
    export_dir = _expand_path(
        str(export_value) if export_value is not None else f"{pki_dir}/export/ansible",
        environment,
    )
    if export_provided and not export_dir.startswith("/"):
        _die("--export-dir must be an absolute path")
    export_parent_path = os.path.dirname(export_dir)
    export_name = os.path.basename(export_dir)
    force = bool(parsed.values.get("--force"))

    require_pki_directory(pki_dir)
    prepare_control_state(pki_dir)
    inventory_path = require_inventory_readable(pki_dir)

    sources = _Sources()
    old_directory: OpenedDirectory | None = None
    stage: OpenedDirectory | None = None
    stage_name: str | None = None
    stage_identity: FileIdentity | None = None
    stage_readiness: TreeReadiness | None = None
    stage_recovery_path: str | None = None
    published = False
    fault: FaultHook | None = None
    pause: PauseHook | None = None
    try:
        with acquire_operational_locks(pki_dir, "export"):
            require_generation_layout(pki_dir)
            _require_trusted_components(export_parent_path, "Export parent")
            _require_private_directory(export_parent_path, "Export parent")
            try:
                pki = OpenedDirectory(
                    pki_dir, policy=DirectoryPolicy(owner=os.geteuid(), mode=0o700)
                )
                export_parent = OpenedDirectory(
                    export_parent_path,
                    policy=DirectoryPolicy(owner=os.geteuid(), forbidden_bits=0o022),
                )
            except FilesystemError:
                _die("PKI or export parent identity changed during validation")
            with pki, export_parent:
                pki_real = os.path.realpath(f"/proc/self/fd/{pki.fileno()}")
                export_parent_real = os.path.realpath(
                    f"/proc/self/fd/{export_parent.fileno()}"
                )
                export_real = f"{export_parent_real}/{export_name}"
                default_real = f"{pki_real}/export/ansible"
                if pki_real == export_real or pki_real.startswith(f"{export_real}/"):
                    _die(
                        f"Export directory must not equal or contain the PKI directory: {export_dir}"
                    )
                if export_real == f"{pki_real}/export":
                    _die(f"Export directory must be below the PKI export directory: {export_dir}")
                if export_real.startswith(f"{pki_real}/") and not export_real.startswith(
                    f"{pki_real}/export/"
                ):
                    _die(
                        f"Export directory inside the PKI tree must be under its export directory: {export_dir}"
                    )

                destination, old_directory, authorization_marker = _authorize_destination(
                    export_parent, export_name, export_real, default_real, sources
                )
                if destination is not ABSENT and not force:
                    _die(f"Export directory exists; use --force to replace it: {export_dir}")

                inventory_source = sources.open(
                    inventory_path,
                    policy=FilePolicy(
                        owner=os.geteuid(), forbidden_bits=0o022, links=1
                    ),
                    label="Service inventory could not be read safely",
                )
                try:
                    inventory = parse_inventory(inventory_source.data)
                except InventoryError as error:
                    _die(str(error))

                active_source = sources.open(
                    f"{pki_dir}/state/active-issuer",
                    policy=FilePolicy(
                        owner=os.geteuid(), mode=0o600, links=1, max_size=4096
                    ),
                    label="PKI issuer state is invalid",
                )
                active_root, active_intermediate = _pair(
                    active_source.data,
                    "Active issuer",
                    active_source.path,
                )
                active_root_path = (
                    f"{pki_dir}/authorities/roots/{active_root}/certs/root-ca.crt"
                )
                active_intermediate_path = (
                    f"{pki_dir}/authorities/intermediates/{active_intermediate}/certs/intermediate-ca.crt"
                )
                active_root_source = sources.open(active_root_path)
                sources.open(active_intermediate_path)
                verification = run_external(
                    (
                        "openssl",
                        "verify",
                        "-CAfile",
                        active_root_path,
                        active_intermediate_path,
                    ),
                    environment,
                )
                sys.stderr.buffer.write(verification.stderr)
                sys.stderr.buffer.flush()
                if verification.status:
                    _die("Active intermediate does not verify against its recorded root")

                selected: list[str] = []
                if services:
                    for service in services:
                        entry = _inventory_service(inventory, service, inventory_path)
                        if entry.key_custody != "managed":
                            _die(
                                "Host-local service cannot be exported through the managed-key "
                                f"Ansible export: {service}"
                            )
                        if not _service_generated(pki_dir, service):
                            _die(
                                f"Generated certificate files are incomplete for service: {service}"
                            )
                        selected.append(service)
                else:
                    for entry in inventory.services:
                        if entry.key_custody == "host-local":
                            _warn(
                                "Skipping host-local service; Ansible export is managed-key-only: "
                                f"{entry.name}"
                            )
                        elif _service_generated(pki_dir, entry.name):
                            selected.append(entry.name)
                        else:
                            _warn(
                                f"Skipping service without generated certificate files: {entry.name}"
                            )
                if not selected:
                    _die("No generated service certificates found to export")

                service_data: list[tuple[str, tuple[bytes, bytes, bytes, bytes]]] = []
                for service in selected:
                    cert, key, chain, fullchain, issuer = _service_paths(pki_dir, service)
                    issuer_source = sources.open(
                        issuer,
                        policy=FilePolicy(
                            owner=os.geteuid(), mode=0o600, links=1, max_size=4096
                        ),
                        label=f"Service {service} issuer manifest is invalid",
                    )
                    root_id, intermediate_id = _pair(
                        issuer_source.data,
                        f"Service {service} issuer",
                        issuer_source.path,
                    )
                    sources.open(
                        f"{pki_dir}/authorities/roots/{root_id}/certs/root-ca.crt"
                    )
                    sources.open(
                        f"{pki_dir}/authorities/intermediates/{intermediate_id}/certs/intermediate-ca.crt"
                    )
                    cert_data = sources.open(cert).data
                    key_data = sources.open(key).data
                    chain_data = sources.open(chain).data
                    fullchain_data = sources.open(fullchain).data
                    service_data.append(
                        (service, (cert_data, key_data, chain_data, fullchain_data))
                    )

                fault = FaultHook(
                    crash_at=environment.get("PLATFORM_PKI_EXPORT_ANSIBLE_CRASH_AT"),
                    failure_at=environment.get("PLATFORM_PKI_EXPORT_ANSIBLE_FAIL_AT"),
                )
                pause = PauseHook(
                    pause_at=environment.get("PLATFORM_PKI_EXPORT_ANSIBLE_PAUSE_AT"),
                    marker=environment.get("PLATFORM_PKI_EXPORT_ANSIBLE_PAUSE_MARKER"),
                    release=environment.get("PLATFORM_PKI_EXPORT_ANSIBLE_PAUSE_RELEASE"),
                )
                stage_name, stage = _reserve_stage(export_parent, export_name)
                stage_recovery_path = _recovery_path(export_parent, stage_name)
                stage_identity = stage.identity
                fault("export-before-stage-build")
                pause("export-before-stage-build")
                _build_stage(
                    stage,
                    active_root_source.data,
                    tuple(service_data),
                )
                fault("export-after-stage-build")
                pause("export-after-stage-build")
                stage.close()
                stage = export_parent.open_directory(
                    stage_name,
                    policy=DirectoryPolicy(owner=os.geteuid(), mode=0o700),
                )
                stage_identity = stage.identity
                stage_readiness = fsync_tree(
                    stage,
                    export_parent,
                    stage_name,
                    fault_hook=fault,
                    pause_hook=pause,
                )
                old_readiness: TreeReadiness | None = None
                if old_directory is not None:
                    old_readiness = fsync_tree(
                        old_directory,
                        export_parent,
                        export_name,
                        allow_symlinks=True,
                        fault_hook=fault,
                        pause_hook=pause,
                    )

                fault("export-before-source-recheck")
                pause("export-before-source-recheck")
                sources.recheck()
                pki.recheck()
                export_parent.recheck()
                current = export_parent.identity_at(export_name)
                if current != destination:
                    _die("Export destination identity changed before publication")

                if destination is ABSENT:
                    try:
                        publish_no_clobber(
                            export_parent,
                            stage_name,
                            stage_identity,
                            export_parent,
                            export_name,
                            readiness=stage_readiness,
                            fault_hook=fault,
                            pause_hook=pause,
                        )
                        published = True
                    except PublicationDestinationExistsError:
                        _die("Export destination appeared before publication")
                    except PublicationAmbiguousError:
                        published = True
                        _warn(
                            f"Ansible export publication requires inspection: {export_real}"
                        )
                        return 1
                else:
                    assert isinstance(destination, FileIdentity)
                    assert old_readiness is not None
                    final_authorization_check = None
                    if authorization_marker is not None:
                        marker = authorization_marker
                        final_authorization_check = lambda: _recheck_marker(
                            marker, export_real
                        )
                    try:
                        result = replace_exact(
                            export_parent,
                            stage_name,
                            stage_identity,
                            export_parent,
                            export_name,
                            destination,
                            source_readiness=stage_readiness,
                            destination_readiness=old_readiness,
                            pre_exchange_check=final_authorization_check,
                            fault_hook=fault,
                            pause_hook=pause,
                        )
                        published = True
                    except PublicationAmbiguousError:
                        published = True
                        _warn(
                            "Ansible export replacement requires inspection; displaced export "
                            f"evidence retained at: {stage_recovery_path}"
                        )
                        return 1
                    try:
                        assert result.old_destination_readiness is not None
                        remove_exact_tree(
                            export_parent,
                            stage_name,
                            result.old_destination_identity,
                            result.old_destination_readiness,
                            fault_hook=fault,
                            pause_hook=pause,
                        )
                    except PublicationError:
                        _warn(
                            "Ansible export was replaced, but displaced export cleanup is incomplete; "
                            f"recovery evidence retained at: {stage_recovery_path}"
                        )
                        return 1

                for service in selected:
                    _ok(f"Exported service: {service}")
                _warn(f"Export contains service private keys: {export_dir}")
                _ok(f"Ansible export ready: {export_dir}")
                return 0
    finally:
        if old_directory is not None:
            old_directory.close()
        if stage is not None:
            stage.close()
        if (
            not published
            and stage_name is not None
            and stage_identity is not None
        ):
            if stage_readiness is None:
                _warn(
                    "Ansible export staging evidence retained because exact cleanup readiness "
                    f"was not completed: {stage_recovery_path}"
                )
            else:
                try:
                    assert fault is not None and pause is not None
                    with OpenedDirectory(export_parent_path) as cleanup_parent:
                        remove_exact_tree(
                            cleanup_parent,
                            stage_name,
                            stage_identity,
                            stage_readiness,
                            fault_hook=fault,
                            pause_hook=pause,
                        )
                except (FilesystemError, PublicationError):
                    _warn(
                        "Ansible export staging cleanup could not be proven complete; "
                        f"private staging evidence retained at: {stage_recovery_path}"
                    )
        sources.close()
    raise AssertionError("unreachable")
