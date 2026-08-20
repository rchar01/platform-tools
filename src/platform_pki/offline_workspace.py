"""Protected custody and staging workspace initialization."""

from __future__ import annotations

import errno
import json
import os
import stat
import sys
from collections.abc import Mapping
from typing import NoReturn

from .errors import ApplicationError
from .filesystem import (
    ABSENT,
    DirectoryPolicy,
    FilePolicy,
    FilesystemError,
    OpenedDirectory,
    fsync_directory,
)
from .operational import validate_service_name
from .parser import ParseResult
from .paths import PathError, trees_are_disjoint, validate_absolute_path
from .publication import PublicationError, atomic_write_bytes


_DIRECTORY_MODE = 0o700
_METADATA_MODE = 0o600
_METADATA_NAME = "README.md"
_RELATIVE_DIRECTORIES = (
    "",
    "media-in",
    "media-in/request",
    "media-in/signer-input",
    "media-in/evidence",
    "work",
    "work/approved",
    "media-out",
    "media-out/approval",
    "media-out/response",
    "media-out/outcome",
)
_PAYLOAD_ROOTS = frozenset(
    (
        "media-in/request",
        "media-in/signer-input",
        "media-in/evidence",
        "work/approved",
        "media-out/approval",
        "media-out/response",
        "media-out/outcome",
    )
)
_ALLOWED_CHILDREN = {
    "": frozenset((_METADATA_NAME, "media-in", "work", "media-out")),
    "media-in": frozenset(("request", "signer-input", "evidence")),
    "media-in/request": frozenset(),
    "media-in/signer-input": frozenset(),
    "media-in/evidence": frozenset(),
    "work": frozenset(("approved",)),
    "work/approved": frozenset(),
    "media-out": frozenset(("approval", "response", "outcome")),
    "media-out/approval": frozenset(),
    "media-out/response": frozenset(),
    "media-out/outcome": frozenset(),
}
_METADATA = (
    b"# Platform PKI Offline Workspace\n"
    b"\n"
    b"This directory is custody and staging space for removable-media PKI exchange.\n"
    b"It is never authoritative signer replay, transaction, candidate, or recovery state.\n"
    b"Authoritative signer state stays in the platform-infrastructure PKI directory,\n"
    b"or in the explicit namespace or PKI directory supplied to signer commands.\n"
    b"Payload contents below leaf staging directories are workflow-owned and not inspected.\n"
)


def _die(message: str) -> NoReturn:
    raise ApplicationError(message)


def _configuration_home(environment: Mapping[str, str]) -> str | None:
    xdg_config_home = environment.get("XDG_CONFIG_HOME")
    if xdg_config_home:
        return xdg_config_home
    home = environment.get("HOME")
    if not home:
        return None
    return f"{home}/.config"


def _resolve_paths(
    parsed: ParseResult, environment: Mapping[str, str]
) -> tuple[str, str | None]:
    configuration_home = _configuration_home(environment)
    root_value = parsed.values.get("--root")
    if root_value is None:
        if configuration_home is None:
            _die("HOME or XDG_CONFIG_HOME is required when --root is absent")
        root = f"{configuration_home}/platform-pki-offline"
    else:
        root = str(root_value)
    authoritative = (
        None
        if configuration_home is None
        else f"{configuration_home}/platform-infrastructure/pki"
    )
    try:
        validate_absolute_path(root)
        if authoritative is not None:
            validate_absolute_path(authoritative)
    except PathError as error:
        _die(f"Offline workspace path is invalid: {error.message}")
    if authoritative is not None and not trees_are_disjoint(root, authoritative):
        _die("Offline workspace root must be disjoint from the authoritative PKI default")
    return root, authoritative


def _validate_trusted_ancestor(directory: OpenedDirectory, uid: int) -> None:
    identity = directory.recheck()
    writable = identity.permissions & 0o022
    sticky = identity.permissions & stat.S_ISVTX
    if identity.uid not in (0, uid) or (writable and not sticky):
        _die("Offline workspace ancestor is not trusted")


def _open_private_directory(parent: OpenedDirectory, name: str) -> OpenedDirectory:
    try:
        return parent.open_directory(
            name,
            policy=DirectoryPolicy(owner=os.geteuid(), mode=_DIRECTORY_MODE),
        )
    except FilesystemError:
        _die("Offline workspace directory is unsafe")


def _create_private_child(
    parent: OpenedDirectory, name: str
) -> tuple[OpenedDirectory, bool]:
    try:
        identity = parent.identity_at(name)
    except FilesystemError:
        _die("Offline workspace path is unsafe")
    if identity is not ABSENT:
        return _open_private_directory(parent, name), False

    created = False
    previous_umask = os.umask(0)
    try:
        try:
            os.mkdir(name, _DIRECTORY_MODE, dir_fd=parent.fileno())
            created = True
        except OSError as error:
            if error.errno != errno.EEXIST:
                _die("Offline workspace directory could not be created")
    finally:
        os.umask(previous_umask)

    child = _open_private_directory(parent, name)
    if created:
        try:
            fsync_directory(parent)
        except FilesystemError:
            child.close()
            _die("Offline workspace directory creation could not be synchronized")
    return child, created


def _open_or_create_root(path: str) -> tuple[OpenedDirectory, bool]:
    components = path[1:].split("/")
    uid = os.geteuid()
    changed = False
    try:
        current = OpenedDirectory("/")
    except FilesystemError:
        _die("Filesystem root could not be inspected")
    try:
        _validate_trusted_ancestor(current, uid)
        for index, name in enumerate(components):
            final = index == len(components) - 1
            try:
                identity = current.identity_at(name)
            except FilesystemError:
                _die("Offline workspace path is unsafe")
            if identity is ABSENT:
                child, created = _create_private_child(current, name)
                changed = changed or created
            else:
                try:
                    child = current.open_directory(name)
                except FilesystemError:
                    _die("Offline workspace path is unsafe")
                if final:
                    try:
                        DirectoryPolicy(
                            owner=uid, mode=_DIRECTORY_MODE
                        ).validate(child.recheck())
                    except FilesystemError:
                        child.close()
                        _die("Offline workspace root is not current-user-owned mode 700")
                else:
                    _validate_trusted_ancestor(child, uid)
            current.close()
            current = child
        return current, changed
    except BaseException:
        current.close()
        raise


def _list_directory(directory: OpenedDirectory) -> frozenset[str]:
    try:
        names = os.listdir(directory.fileno())
        directory.recheck()
    except (OSError, FilesystemError):
        _die("Offline workspace directory could not be enumerated safely")
    return frozenset(names)


def _validate_metadata(workspace: OpenedDirectory) -> bool:
    try:
        identity = workspace.identity_at(_METADATA_NAME)
    except FilesystemError:
        _die("Offline workspace metadata is unsafe")
    if identity is ABSENT:
        return False
    try:
        with workspace.open_file(
            _METADATA_NAME,
            policy=FilePolicy(
                owner=os.geteuid(),
                mode=_METADATA_MODE,
                links=1,
                max_size=len(_METADATA),
            ),
        ) as metadata:
            if metadata.read(len(_METADATA)) != _METADATA:
                _die("Offline workspace metadata content changed")
            metadata.recheck()
    except FilesystemError:
        _die("Offline workspace metadata is unsafe")
    return True


def _validate_existing_tree(workspace: OpenedDirectory) -> bool:
    metadata_exists = False

    def validate_directory(directory: OpenedDirectory, relative: str) -> None:
        nonlocal metadata_exists
        if relative in _PAYLOAD_ROOTS:
            directory.recheck()
            return
        names = _list_directory(directory)
        unexpected = names - _ALLOWED_CHILDREN[relative]
        if unexpected:
            _die("Offline workspace contains unexpected content")
        if not relative:
            metadata_exists = _validate_metadata(directory)
        for name in sorted(names - {_METADATA_NAME}, key=os.fsencode):
            child = _open_private_directory(directory, name)
            try:
                child_relative = name if not relative else f"{relative}/{name}"
                validate_directory(child, child_relative)
            finally:
                child.close()

    validate_directory(workspace, "")
    return metadata_exists


def _ensure_relative_directory(
    workspace: OpenedDirectory, relative: str
) -> bool:
    current: OpenedDirectory | None = None
    parent = workspace
    changed = False
    try:
        for name in relative.split("/"):
            child, created = _create_private_child(parent, name)
            changed = changed or created
            if current is not None:
                current.close()
            current = child
            parent = child
        return changed
    finally:
        if current is not None:
            current.close()


def _create_metadata(workspace: OpenedDirectory) -> None:
    try:
        atomic_write_bytes(
            workspace,
            _METADATA_NAME,
            _METADATA,
            mode=_METADATA_MODE,
            owner=os.geteuid(),
        )
    except PublicationError:
        _die("Offline workspace metadata could not be published safely")


def initialize_offline_workspace(
    parsed: ParseResult,
    *,
    environment: Mapping[str, str] | None = None,
) -> int:
    """Create one exact owner-only offline custody and staging skeleton."""

    effective_environment = os.environ if environment is None else environment
    service = str(parsed["service"])
    validate_service_name(service)
    root, authoritative = _resolve_paths(parsed, effective_environment)
    workspace_path = f"{root}/{service}"

    root_directory, changed = _open_or_create_root(root)
    try:
        try:
            workspace_identity = root_directory.identity_at(service)
        except FilesystemError:
            _die("Offline workspace path is unsafe")
        if workspace_identity is ABSENT:
            workspace, created = _create_private_child(root_directory, service)
            changed = changed or created
            metadata_exists = False
        else:
            workspace = _open_private_directory(root_directory, service)
            metadata_exists = _validate_existing_tree(workspace)

        try:
            for relative in _RELATIVE_DIRECTORIES[1:]:
                changed = _ensure_relative_directory(workspace, relative) or changed
            if not metadata_exists:
                _create_metadata(workspace)
                changed = True
            if not _validate_existing_tree(workspace):
                _die("Offline workspace metadata is absent after publication")
            workspace.recheck()
        finally:
            workspace.close()
    finally:
        root_directory.close()

    directories = [
        workspace_path if not relative else f"{workspace_path}/{relative}"
        for relative in _RELATIVE_DIRECTORIES
    ]
    result = {
        "status": "created" if changed else "existing",
        "service": service,
        "root": root,
        "workspace_dir": workspace_path,
        "authoritative_pki_default": authoritative,
        "directories": directories,
    }
    sys.stdout.write(json.dumps(result, ensure_ascii=True, separators=(",", ":")) + "\n")
    return 0
