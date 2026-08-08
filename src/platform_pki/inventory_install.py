"""Install reviewed private inventory bytes into protected PKI state."""

from __future__ import annotations

import os
import stat
import sys
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from typing import NoReturn

from .errors import ApplicationError
from .faults import PauseHook
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
from .inventory import InventoryError, parse_inventory
from .operational import (
    acquire_operational_locks,
    require_pilot_common_library,
    run_external,
)
from .parser import ParseResult
from .publication import (
    GuardedExchangeRaceError,
    PublicationAmbiguousError,
    PublicationDestinationExistsError,
    PublicationError,
    PublicationIdentityError,
    StagedFile,
    exchange_exact,
    exchange_guarded_regular_files,
    publish_no_clobber,
    stage_file_bytes,
)
from .subprocesses import ProcessSpawnError


_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _die(message: str) -> NoReturn:
    raise ApplicationError(message)


def _expand_path(path: str, environment: Mapping[str, str]) -> str:
    if path == "~":
        return environment.get("HOME", "")
    if path.startswith("~/"):
        return f"{environment.get('HOME', '')}/{path[2:]}"
    return path


def _default_namespace(environment: Mapping[str, str]) -> str:
    base = environment.get("XDG_CONFIG_HOME") or (
        f"{environment.get('HOME', '')}/.config"
    )
    return f"{base}/platform-infrastructure"


def _components(path: str) -> Iterator[str]:
    current = "/" if path.startswith("/") else ""
    for component in path.split("/"):
        if not component:
            continue
        if current == "/":
            current = f"/{component}"
        elif current:
            current = f"{current}/{component}"
        else:
            current = component
        yield current


def _lstat(path: str) -> os.stat_result | None:
    try:
        return os.lstat(path)
    except OSError:
        return None


def _require_no_symlink_components(path: str, label: str) -> None:
    for current in _components(path):
        result = _lstat(current)
        if result is not None and stat.S_ISLNK(result.st_mode):
            _die(f"{label} path component must not be a symlink: {current}")


def _require_trusted_ancestors(path: str, label: str) -> None:
    uid = os.geteuid()
    for current in _components(path):
        result = _lstat(current)
        if result is None or not stat.S_ISDIR(result.st_mode):
            _die(
                f"{label} ancestor must be a non-symlink directory: {current}"
            )
        permissions = stat.S_IMODE(result.st_mode)
        if result.st_uid not in (uid, 0):
            _die(
                f"{label} ancestor is not owned by current user or root: {current}"
            )
        if permissions & 0o022 and not permissions & stat.S_ISVTX:
            _die(
                f"{label} ancestor is group- or world-writable without sticky bit: {current}"
            )


def _directory_resolution_state(result: os.stat_result) -> tuple[int, ...]:
    return (
        result.st_dev,
        result.st_ino,
        stat.S_IMODE(result.st_mode),
        result.st_uid,
        result.st_mtime_ns // 1_000_000_000,
        result.st_ctime_ns // 1_000_000_000,
    )


def _resolve_existing_directory(path: str, label: str) -> str:
    result = _lstat(path)
    if result is None:
        _die(f"Cannot inspect {label.lower()}: {path}")
    assert result is not None
    before = _directory_resolution_state(result)
    descriptor = -1
    try:
        descriptor = os.open(path, _DIRECTORY_FLAGS)
        opened = os.fstat(descriptor)
        after = _lstat(path)
        if (
            after is None
            or _directory_resolution_state(opened) != before
            or _directory_resolution_state(after) != before
        ):
            _die(f"{label} changed during resolution")
        return os.path.realpath(f"/proc/self/fd/{descriptor}")
    except ApplicationError:
        raise
    except OSError:
        _die(f"{label} does not exist: {path}")
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _require_private_directory(path: str, label: str, *, exact: bool = False) -> None:
    result = _lstat(path)
    if result is None or not stat.S_ISDIR(result.st_mode):
        _die(f"{label} must be a non-symlink directory: {path}")
    assert result is not None
    permissions = stat.S_IMODE(result.st_mode)
    if result.st_uid != os.geteuid():
        _die(f"{label} is not owned by the current user: {path}")
    if exact and permissions != 0o700:
        _die(f"{label} must be current-user-owned with mode 700: {path}")
    if not exact and permissions & 0o022:
        _die(f"{label} is group- or world-writable: {path}")


def _prepare_control_state(pki_dir: str) -> None:
    _require_private_directory(pki_dir, "PKI directory", exact=True)
    _require_no_symlink_components(pki_dir, "PKI directory")
    for relative in (
        "locks",
        "state",
        "state/rollover",
        "state/rollovers",
        "state/generation-reservations",
    ):
        path = f"{pki_dir}/{relative}"
        if not os.path.lexists(path):
            try:
                os.mkdir(path, 0o700)
            except FileExistsError:
                pass
            except OSError:
                _die(f"Cannot create PKI control directory: {path}")
        _require_private_directory(path, "PKI control directory", exact=True)


def _require_atomic_mv(environment: Mapping[str, str]) -> None:
    try:
        result = run_external(("mv", "--help"), environment)
    except ProcessSpawnError:
        _die("GNU mv is required")
    if result.status:
        _die("GNU mv is required")
    if b"--no-copy" not in result.stdout or b"none-fail" not in result.stdout:
        _die("GNU mv with --no-copy and --update=none-fail is required")


def _same_inode(first: FileIdentity, second: FileIdentity) -> bool:
    return (first.dev, first.ino, first.kind) == (second.dev, second.ino, second.kind)


def _identity(parent: OpenedDirectory, name: str) -> FileIdentity | object:
    try:
        return parent.identity_at(name)
    except FilesystemError:
        raise PublicationIdentityError() from None


def _remove_exact_name(
    parent: OpenedDirectory,
    name: str,
    expected: FileIdentity,
) -> bool:
    try:
        current = parent.identity_at(name)
        if (
            not isinstance(current, FileIdentity)
            or current.kind != "regular"
            or not _same_inode(current, expected)
        ):
            return False
        os.unlink(name, dir_fd=parent.fileno())
        return parent.identity_at(name) is ABSENT
    except (OSError, FilesystemError):
        return False


@dataclass(slots=True)
class _Artifacts:
    stage: StagedFile | None = None
    stage_identity: FileIdentity | None = None
    guard_base: StagedFile | None = None
    guard_base_identity: FileIdentity | None = None
    guard_link: str | None = None
    guard_link_identity: FileIdentity | None = None
    preserve: bool = False


class _PreservePublication(Exception):
    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)


def _artifact_path(parent: OpenedDirectory, name: str | None) -> str:
    return "none" if name is None else f"/proc/self/fd/{parent.fileno()}/{name}"


def _preserve(
    message: str,
    parent: OpenedDirectory,
    artifacts: _Artifacts,
) -> NoReturn:
    artifacts.preserve = True
    stage_name = artifacts.stage.name if artifacts.stage is not None else None
    base_name = (
        artifacts.guard_base.name if artifacts.guard_base is not None else None
    )
    raise _PreservePublication(
        f"{message}; recovery artifacts: "
        f"{_artifact_path(parent, stage_name)} "
        f"{_artifact_path(parent, artifacts.guard_link)} "
        f"{_artifact_path(parent, base_name)}"
    )


def _cleanup_artifacts(parent: OpenedDirectory, artifacts: _Artifacts) -> bool:
    failed = False
    if artifacts.stage is not None and artifacts.stage_identity is not None:
        if _remove_exact_name(parent, artifacts.stage.name, artifacts.stage_identity):
            artifacts.stage.mark_consumed()
            artifacts.stage = None
            artifacts.stage_identity = None
        else:
            failed = True
    if artifacts.guard_link is not None and artifacts.guard_link_identity is not None:
        if _remove_exact_name(
            parent, artifacts.guard_link, artifacts.guard_link_identity
        ):
            artifacts.guard_link = None
            artifacts.guard_link_identity = None
        else:
            failed = True
    if artifacts.guard_base is not None and artifacts.guard_base_identity is not None:
        if _remove_exact_name(
            parent, artifacts.guard_base.name, artifacts.guard_base_identity
        ):
            artifacts.guard_base.mark_consumed()
            artifacts.guard_base = None
            artifacts.guard_base_identity = None
        else:
            failed = True
    return not failed


def _close_artifacts(artifacts: _Artifacts) -> None:
    for staged in (artifacts.guard_base, artifacts.stage):
        if staged is not None:
            try:
                staged.close()
            except PublicationError:
                pass


def _probe_exchange(
    parent: OpenedDirectory,
    *,
    forced_fallback: bool,
) -> bool:
    if forced_fallback:
        return False
    first = stage_file_bytes(parent, "platform-pki-exchange-a", b"")
    second: StagedFile | None = None
    try:
        second = stage_file_bytes(parent, "platform-pki-exchange-b", b"")
        try:
            exchange_exact(
                parent,
                first.name,
                first.identity,
                parent,
                second.name,
                second.identity,
            )
        except PublicationError:
            return False
        return True
    finally:
        for staged in (first, second):
            if staged is None:
                continue
            current = _identity(parent, staged.name)
            if isinstance(current, FileIdentity):
                _remove_exact_name(parent, staged.name, current)
            staged.mark_consumed()
            staged.close()


def _snapshot_destination(parent: OpenedDirectory) -> tuple[FileIdentity | object, int | None]:
    destination = _identity(parent, "services.yml")
    if destination is ABSENT:
        return ABSENT, None
    if not isinstance(destination, FileIdentity) or destination.kind != "regular":
        _die(
            "Inventory destination must be a non-symlink regular file: "
            "/proc/self/fd/%d/services.yml" % parent.fileno()
        )
    if destination.uid != os.geteuid():
        _die(
            "Inventory destination is not owned by the current user: "
            "/proc/self/fd/%d/services.yml" % parent.fileno()
        )
    if destination.links != 1:
        _die(
            "Inventory destination must not be hard-linked: "
            "/proc/self/fd/%d/services.yml" % parent.fileno()
        )
    if destination.permissions & 0o022:
        _die(
            "Inventory destination is group- or world-writable: "
            "/proc/self/fd/%d/services.yml" % parent.fileno()
        )
    return destination, destination.permissions


def _recheck_destination(
    parent: OpenedDirectory,
    expected: FileIdentity | object,
) -> None:
    current = _identity(parent, "services.yml")
    if expected is ABSENT:
        if current is not ABSENT:
            _die("Inventory destination changed after validation")
        return
    assert isinstance(expected, FileIdentity)
    if not isinstance(current, FileIdentity) or not _same_inode(current, expected):
        _die("Inventory destination identity changed after validation")


def _create_guard(
    parent: OpenedDirectory,
    destination: FileIdentity,
    artifacts: _Artifacts,
) -> FileIdentity:
    try:
        guard_base = stage_file_bytes(parent, "platform-pki-inventory-guard", b"")
    except PublicationError:
        _die("Cannot create inventory publication guard")
    artifacts.guard_base = guard_base
    artifacts.guard_base_identity = guard_base.identity
    guard_link = f"{guard_base.name}.link"
    try:
        os.link(
            "services.yml",
            guard_link,
            src_dir_fd=parent.fileno(),
            dst_dir_fd=parent.fileno(),
            follow_symlinks=False,
        )
    except OSError:
        _die("Inventory destination changed before publication guard")
    artifacts.guard_link = guard_link
    guarded = _identity(parent, guard_link)
    current = _identity(parent, "services.yml")
    if (
        not isinstance(guarded, FileIdentity)
        or not isinstance(current, FileIdentity)
        or not _same_inode(guarded, destination)
        or not _same_inode(current, destination)
        or guarded != current
    ):
        _die("Inventory destination identity changed before publication")
    artifacts.guard_link_identity = guarded
    return guarded


def _publish_fallback(
    parent: OpenedDirectory,
    destination: FileIdentity,
    guarded: FileIdentity,
    pause: PauseHook,
    artifacts: _Artifacts,
) -> None:
    assert artifacts.stage is not None
    assert artifacts.stage_identity is not None
    assert artifacts.guard_link is not None
    stage = artifacts.stage
    stage_identity = artifacts.stage_identity
    _recheck_destination(parent, destination)
    guard = _identity(parent, artifacts.guard_link)
    if not isinstance(guard, FileIdentity) or not _same_inode(guard, guarded):
        _die("Inventory guard changed before fallback publication")
    pause("guarded-exchange-before-mutation")
    try:
        os.rename(
            stage.name,
            "services.yml",
            src_dir_fd=parent.fileno(),
            dst_dir_fd=parent.fileno(),
        )
    except OSError:
        _preserve("Cannot atomically replace active inventory", parent, artifacts)
    pause("guarded-exchange-after-mutation")
    published = _identity(parent, "services.yml")
    guard = _identity(parent, artifacts.guard_link)
    if (
        not isinstance(published, FileIdentity)
        or not isinstance(guard, FileIdentity)
        or not _same_inode(published, stage_identity)
        or not _same_inode(guard, guarded)
    ):
        _preserve("Fallback inventory publication identity check failed", parent, artifacts)
    stage.mark_consumed()
    artifacts.stage = None
    artifacts.stage_identity = None


def _install_locked(
    pki_dir: str,
    pki_real: str,
    source: OpenedFile,
    source_parent: OpenedDirectory,
    private_repo: OpenedDirectory,
    inventory_parent: OpenedDirectory,
    environment: Mapping[str, str],
    pause: PauseHook,
    exchange_supported: bool,
) -> int:
    artifacts = _Artifacts()
    preserve_error: _PreservePublication | None = None
    cleanup_ok = True
    try:
        private_repo.recheck()
        source_parent.recheck()
        with OpenedDirectory(
            pki_real,
            policy=DirectoryPolicy(owner=os.geteuid(), mode=0o700),
        ) as pki:
            pki.recheck()
        inventory_parent.recheck()

        destination, destination_mode = _snapshot_destination(inventory_parent)
        pause("inventory-source-before-read")
        try:
            source_bytes = source.read(source.identity.size)
        except FilesystemError:
            _die("Inventory source changed while staging")
        private_repo.recheck()
        source_parent.recheck()
        try:
            stage = stage_file_bytes(
                inventory_parent,
                "platform-pki-inventory-install",
                source_bytes,
                mode=0o600,
                pause_hook=pause,
            )
        except PublicationError:
            _die("Cannot create inventory staging file")
        artifacts.stage = stage
        artifacts.stage_identity = stage.identity
        try:
            source.recheck()
            source_parent.recheck()
            private_repo.recheck()
        except FilesystemError:
            _die("Inventory source changed while staging")
        try:
            parse_inventory(source_bytes)
        except InventoryError as error:
            _die(str(error))

        if destination is not ABSENT:
            assert isinstance(destination, FileIdentity)
            destination_bytes = b""
            try:
                with inventory_parent.open_file(
                    "services.yml",
                    policy=FilePolicy(
                        owner=os.geteuid(), forbidden_bits=0o022, links=1
                    ),
                    expected_identity=destination,
                ) as opened_destination:
                    destination_bytes = opened_destination.read(
                        opened_destination.identity.size
                    )
            except FilesystemError:
                _die("Inventory destination changed after validation")
            if destination_bytes == source_bytes and destination_mode == 0o600:
                if not _cleanup_artifacts(inventory_parent, artifacts):
                    print(
                        "[WARN] Inventory publication requires recovery; retained artifacts under: "
                        f"{os.path.realpath(f'/proc/self/fd/{inventory_parent.fileno()}')}",
                        file=sys.stderr,
                        flush=True,
                    )
                    artifacts.preserve = True
                    return 1
                print(
                    f"[OK] Inventory already current: {pki_dir}/inventory/services.yml",
                    flush=True,
                )
                return 0
            status = "normalized" if destination_bytes == source_bytes else "updated"
        else:
            status = "installed"

        inventory_parent.recheck()
        _recheck_destination(inventory_parent, destination)
        if destination is ABSENT:
            try:
                publish_no_clobber(
                    inventory_parent,
                    stage.name,
                    stage.identity,
                    inventory_parent,
                    "services.yml",
                    pause_hook=pause,
                )
            except PublicationDestinationExistsError:
                _die("Inventory destination appeared before publication")
            except PublicationAmbiguousError:
                _preserve("Published inventory identity is invalid", inventory_parent, artifacts)
            except PublicationError:
                _die("Inventory destination appeared before publication")
            stage.mark_consumed()
            artifacts.stage = None
            artifacts.stage_identity = None
        else:
            assert isinstance(destination, FileIdentity)
            guarded = _create_guard(inventory_parent, destination, artifacts)
            guard_name = artifacts.guard_link
            assert guard_name is not None
            if exchange_supported:
                try:
                    result = exchange_guarded_regular_files(
                        inventory_parent,
                        stage.name,
                        stage.identity,
                        "services.yml",
                        guarded,
                        guard_name,
                        guarded,
                        pause_hook=pause,
                    )
                except GuardedExchangeRaceError:
                    _die("Inventory destination changed during publication")
                except PublicationAmbiguousError:
                    _preserve("Inventory changed during publication", inventory_parent, artifacts)
                except PublicationError:
                    _die("Cannot exchange staged and active inventory")
                artifacts.stage_identity = result.first_identity
            else:
                _publish_fallback(
                    inventory_parent,
                    destination,
                    guarded,
                    pause,
                    artifacts,
                )

            if artifacts.guard_link is not None:
                assert artifacts.guard_link_identity is not None
                if not _remove_exact_name(
                    inventory_parent,
                    artifacts.guard_link,
                    artifacts.guard_link_identity,
                ):
                    _preserve(
                        "Cannot remove identity-matched inventory publication guard",
                        inventory_parent,
                        artifacts,
                    )
                artifacts.guard_link = None
                artifacts.guard_link_identity = None
            if artifacts.guard_base is not None:
                assert artifacts.guard_base_identity is not None
                if not _remove_exact_name(
                    inventory_parent,
                    artifacts.guard_base.name,
                    artifacts.guard_base_identity,
                ):
                    _preserve(
                        "Cannot remove identity-matched inventory publication guard base",
                        inventory_parent,
                        artifacts,
                    )
                artifacts.guard_base.mark_consumed()
                artifacts.guard_base = None
                artifacts.guard_base_identity = None
            if artifacts.stage is not None:
                assert artifacts.stage_identity is not None
                if not _remove_exact_name(
                    inventory_parent,
                    artifacts.stage.name,
                    artifacts.stage_identity,
                ):
                    _preserve(
                        "Cannot remove identity-matched previous inventory",
                        inventory_parent,
                        artifacts,
                    )
                artifacts.stage.mark_consumed()
                artifacts.stage = None
                artifacts.stage_identity = None

        inventory_parent.recheck()
        print(
            f"[OK] Inventory {status}: {pki_dir}/inventory/services.yml",
            flush=True,
        )
        return 0
    except _PreservePublication as error:
        preserve_error = error
        print(f"[ERROR] {error.message}", file=sys.stderr, flush=True)
        print(
            "[WARN] Inventory publication requires recovery; retained artifacts under: "
            f"{os.path.realpath(f'/proc/self/fd/{inventory_parent.fileno()}')}",
            file=sys.stderr,
            flush=True,
        )
        return 1
    finally:
        if preserve_error is None and not artifacts.preserve:
            cleanup_ok = _cleanup_artifacts(inventory_parent, artifacts)
            if not cleanup_ok:
                print(
                    "[WARN] Inventory publication requires recovery; retained artifacts under: "
                    f"{os.path.realpath(f'/proc/self/fd/{inventory_parent.fileno()}')}",
                    file=sys.stderr,
                    flush=True,
                )
        _close_artifacts(artifacts)


def install_inventory(parsed: ParseResult) -> int:
    """Run the Bash-compatible inventory installation workflow."""

    environment = dict(os.environ)
    require_pilot_common_library(environment)
    namespace_value = parsed.values.get("--namespace")
    namespace = _expand_path(
        str(namespace_value)
        if namespace_value is not None
        else _default_namespace(environment),
        environment,
    )
    pki_value = parsed.values.get("--pki-dir")
    pki_dir = (
        f"{namespace}/pki"
        if pki_value is None
        else _expand_path(str(pki_value), environment)
    )
    try:
        physical_cwd = os.getcwd()
    except OSError:
        _die("Cannot resolve physical current directory")
    private_value = _expand_path(str(parsed["--private-repo"]), environment)
    private_path = (
        private_value
        if private_value.startswith("/")
        else f"{physical_cwd}/{private_value}"
    )

    _require_no_symlink_components(private_path, "Private repository")
    _require_trusted_ancestors(private_path, "Private repository")
    private_real = _resolve_existing_directory(private_path, "Private repository")
    source_path = f"{private_real}/pki/services.yml"
    source_parent_path = os.path.dirname(source_path)
    _require_trusted_ancestors(source_parent_path, "Inventory source")
    source_result = _lstat(source_path)
    if (
        source_result is None
        or not stat.S_ISREG(source_result.st_mode)
        or not os.access(source_path, os.R_OK)
    ):
        _die(
            "Inventory source must be a readable non-symlink regular file: "
            f"{source_path}"
        )
    assert source_result is not None
    source_identity = identity_from_stat(source_result)
    if source_identity.uid != os.geteuid():
        _die(f"Inventory source is not owned by the current user: {source_path}")
    if source_identity.links != 1:
        _die(f"Inventory source must not be hard-linked: {source_path}")
    if source_identity.permissions & 0o022:
        _die(f"Inventory source is group- or world-writable: {source_path}")

    _require_no_symlink_components(pki_dir, "PKI directory")
    if not os.path.isdir(pki_dir):
        _die(
            "PKI directory does not exist; run platform-pki-init first: "
            f"{pki_dir}"
        )
    _prepare_control_state(pki_dir)
    if not any(
        os.access(os.path.join(directory, "ln"), os.X_OK)
        for directory in environment.get("PATH", "").split(os.pathsep)
        if directory
    ):
        _die("ln is required")
    _require_atomic_mv(environment)
    pki_real = _resolve_existing_directory(pki_dir, "PKI directory")
    if private_real == pki_real or private_real.startswith(f"{pki_real}/"):
        _die("Private repository must not resolve inside the PKI destination tree")
    _require_private_directory(pki_dir, "PKI directory")
    _require_private_directory(f"{pki_dir}/inventory", "Inventory directory")

    pause = PauseHook(
        pause_at=environment.get("PLATFORM_PKI_INVENTORY_INSTALL_PAUSE_AT"),
        marker=environment.get("PLATFORM_PKI_INVENTORY_INSTALL_PAUSE_MARKER"),
        release=environment.get("PLATFORM_PKI_INVENTORY_INSTALL_PAUSE_RELEASE"),
    )
    try:
        with OpenedDirectory(private_real) as private_repo:
            with OpenedDirectory(source_parent_path) as source_parent:
                with source_parent.open_file(
                    "services.yml",
                    policy=FilePolicy(
                        owner=os.geteuid(), forbidden_bits=0o022, links=1
                    ),
                    expected_identity=source_identity,
                ) as source:
                    with OpenedDirectory(
                        f"{pki_real}/inventory",
                        policy=DirectoryPolicy(
                            owner=os.geteuid(), forbidden_bits=0o022
                        ),
                    ) as inventory_parent:
                        exchange_supported = _probe_exchange(
                            inventory_parent,
                            forced_fallback=(
                                environment.get("PLATFORM_PKI_FORCE_RENAME_FALLBACK")
                                == "1"
                            ),
                        )
                        with acquire_operational_locks(pki_real, "inventory"):
                            from .operational import require_no_unresolved_state

                            require_no_unresolved_state(pki_real)
                            return _install_locked(
                                pki_dir,
                                pki_real,
                                source,
                                source_parent,
                                private_repo,
                                inventory_parent,
                                environment,
                                pause,
                                exchange_supported,
                            )
    except FilesystemError:
        _die("Inventory source changed during validation")
    raise AssertionError("unreachable")
