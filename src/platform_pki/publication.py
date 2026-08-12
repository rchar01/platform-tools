"""Linux descriptor-bound durable publication primitives.

Callers must hold the required cooperative lifecycle/operation locks and own
stage names exclusively. Linux has no identity-conditional compare-and-swap
exchange, so a noncooperating same-UID writer can race the final checks. Exact
regular-file unlink has the additional unavoidable check-to-``unlinkat`` race
because Python exposes no unlink-by-handle. Cooperative replacement at exposed
checkpoints is detected and the competing object is preserved.
"""

from __future__ import annotations

import ctypes
import errno
import hashlib
import os
import secrets
import stat
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from types import TracebackType

from . import filesystem
from .errors import ApplicationError
from .faults import DEFAULT_FAULT_HOOK, DEFAULT_PAUSE_HOOK
from .filesystem import (
    ABSENT,
    DirectoryIdentity,
    FileIdentity,
    FileObjectState,
    FilesystemError,
    OpenedDirectory,
    OpenedFile,
    identity_from_stat,
)


_RENAME_NOREPLACE = 1
_RENAME_EXCHANGE = 2
_STAGE_ATTEMPTS = 16
_WRITE_CHUNK = 64 * 1024
_TREE_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
_TREE_DIRECTORY_FLAGS = _TREE_FILE_FLAGS | os.O_DIRECTORY
_TREE_SYMLINK_FLAGS = os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC

_CHECKPOINTS = (
    "stage-before-create",
    "stage-after-create",
    "stage-before-write",
    "stage-after-write",
    "stage-before-file-fsync",
    "stage-after-file-fsync",
    "stage-before-final-validation",
    "stage-after-final-validation",
    "publication-before-mutation",
    "publication-after-mutation",
    "publication-before-parent-fsync",
    "publication-after-parent-fsync",
    "publication-before-final-validation",
    "publication-after-final-validation",
    "exchange-before-mutation",
    "exchange-after-mutation",
    "exchange-before-parent-fsync",
    "exchange-after-parent-fsync",
    "exchange-before-final-validation",
    "exchange-after-final-validation",
    "guarded-exchange-before-mutation",
    "guarded-exchange-after-mutation",
    "replacement-before-exchange",
    "replacement-before-final-authorization",
    "replacement-after-exchange",
    "replacement-after-exchange-durability",
    "replacement-before-old-disposition",
    "replacement-after-old-disposition",
    "replacement-terminal-validation",
    "cleanup-before-unlink",
    "cleanup-after-unlink",
    "cleanup-before-parent-fsync",
    "cleanup-after-parent-fsync",
    "tree-before-node-fsync",
    "tree-after-node-fsync",
    "tree-before-parent-fsync",
    "tree-after-parent-fsync",
    "tree-before-final-validation",
    "tree-after-final-validation",
    "tree-before-child-final-name-check",
    "tree-after-child-final-name-check",
    "tree-cleanup-before-mutation",
    "tree-cleanup-before-entry-unlink",
    "tree-cleanup-before-directory-rmdir",
    "tree-cleanup-before-root-rmdir",
    "tree-cleanup-after-mutation",
    "tree-cleanup-before-parent-fsync",
    "tree-cleanup-after-parent-fsync",
)
PUBLICATION_CHECKPOINTS = _CHECKPOINTS

Hook = Callable[[str], None]


class PublicationError(ApplicationError):
    """A static publication failure safe to render without paths or data."""


class PublicationStageError(PublicationError):
    def __init__(self) -> None:
        super().__init__("Publication staging failed")


class PublicationPolicyError(PublicationError):
    def __init__(self) -> None:
        super().__init__("Publication object does not satisfy its policy")


class PublicationIdentityError(PublicationError):
    def __init__(self) -> None:
        super().__init__("Publication object identity changed")


class PublicationDestinationExistsError(PublicationError):
    def __init__(self) -> None:
        super().__init__("Publication destination already exists")


class PublicationCrossDeviceError(PublicationError):
    def __init__(self) -> None:
        super().__init__("Publication requires one filesystem")


class PublicationMutationError(PublicationError):
    def __init__(self) -> None:
        super().__init__("Atomic publication mutation failed")


class PublicationAmbiguousError(PublicationError):
    """A failure after mutation whose observable state must be retained."""

    def __init__(self) -> None:
        super().__init__("Publication may have completed and requires inspection")


class PublicationDurabilityError(PublicationAmbiguousError):
    def __init__(self) -> None:
        ApplicationError.__init__(
            self,
            "Publication changed names but durability is not confirmed",
        )


class PublicationValidationError(PublicationAmbiguousError):
    def __init__(self) -> None:
        ApplicationError.__init__(
            self,
            "Publication changed names but final identity is not confirmed",
        )


class PublicationCleanupError(PublicationError):
    def __init__(self) -> None:
        super().__init__("Publication cleanup failed")


class PublicationCleanupAmbiguousError(PublicationAmbiguousError):
    def __init__(self) -> None:
        ApplicationError.__init__(
            self,
            "Publication cleanup changed the namespace and requires inspection",
        )


class PublicationReplacementAmbiguousError(PublicationAmbiguousError):
    def __init__(self) -> None:
        ApplicationError.__init__(
            self,
            "Publication replaced the destination and requires inspection",
        )


class PublicationReplacementCleanupError(PublicationReplacementAmbiguousError):
    def __init__(self) -> None:
        ApplicationError.__init__(
            self,
            "Publication replaced the destination but old-state cleanup is incomplete",
        )


class GuardedExchangeRaceError(PublicationError):
    """A guarded exchange race was restored to its pre-exchange names."""

    def __init__(self) -> None:
        super().__init__("Guarded publication destination changed")


class PublicationTreeError(PublicationError):
    def __init__(self) -> None:
        super().__init__("Publication tree could not be synchronized safely")


class PublicationTreeCleanupError(PublicationReplacementCleanupError):
    def __init__(self) -> None:
        ApplicationError.__init__(
            self,
            "Publication replaced the destination but displaced-tree cleanup is incomplete",
        )


@dataclass(frozen=True, slots=True)
class PublicationResult:
    """The final root identity and the operation's pinned parent identities."""

    identity: FileIdentity
    source_parent: DirectoryIdentity
    destination_parent: DirectoryIdentity


@dataclass(frozen=True, slots=True)
class ExchangeResult:
    """Final root identities, in first-name then second-name order."""

    first_identity: FileIdentity
    second_identity: FileIdentity
    first_parent: DirectoryIdentity
    second_parent: DirectoryIdentity


class ReplacementCleanupDisposition(Enum):
    """Terminal disposition of the exact old destination."""

    REMOVED = "removed"
    RETAINED = "retained"


@dataclass(frozen=True, slots=True)
class ReplacementResult:
    """Final replacement identity and exact displaced-state evidence."""

    destination_identity: FileIdentity
    old_destination_identity: FileIdentity
    cleanup_disposition: ReplacementCleanupDisposition
    old_destination_readiness: TreeReadiness | None = field(repr=False)
    source_parent: DirectoryIdentity
    destination_parent: DirectoryIdentity


@dataclass(frozen=True, slots=True)
class _SymlinkIdentity:
    dev: int
    ino: int
    uid: int
    permissions: int
    links: int
    size: int
    mtime_ns: int
    ctime_ns: int
    kind: str = "symlink"


def _symlink_identity(result: os.stat_result) -> _SymlinkIdentity:
    if not stat.S_ISLNK(result.st_mode):
        raise PublicationTreeError()
    return _SymlinkIdentity(
        result.st_dev,
        result.st_ino,
        result.st_uid,
        stat.S_IMODE(result.st_mode),
        result.st_nlink,
        result.st_size,
        result.st_mtime_ns,
        result.st_ctime_ns,
    )


def _same_symlink_inode(first: _SymlinkIdentity, second: _SymlinkIdentity) -> bool:
    return first.dev == second.dev and first.ino == second.ino


@dataclass(frozen=True, slots=True)
class _TreeEntry:
    name: str
    identity: FileIdentity | _SymlinkIdentity
    digest: bytes | None = field(repr=False)
    children: tuple[_TreeEntry, ...] = ()


@dataclass(frozen=True, slots=True, init=False)
class TreeReadiness:
    """Immutable parent-bound evidence that an exact tree was synchronized."""

    root_identity: FileIdentity
    parent_identity: DirectoryIdentity
    root_name: str
    snapshot: tuple[_TreeEntry, ...] = field(repr=False)
    root_digest: bytes | None = field(default=None, repr=False)
    allows_symlinks: bool = field(default=False, repr=False)

    def __init__(self, *_arguments: object, **_keywords: object) -> None:
        raise TypeError("TreeReadiness values are created only by fsync_tree")

    @classmethod
    def _create(
        cls,
        root_identity: FileIdentity,
        parent_identity: DirectoryIdentity,
        root_name: str,
        snapshot: tuple[_TreeEntry, ...],
        root_digest: bytes | None,
        allows_symlinks: bool,
    ) -> TreeReadiness:
        readiness = object.__new__(cls)
        object.__setattr__(readiness, "root_identity", root_identity)
        object.__setattr__(readiness, "parent_identity", parent_identity)
        object.__setattr__(readiness, "root_name", root_name)
        object.__setattr__(readiness, "snapshot", snapshot)
        object.__setattr__(readiness, "root_digest", root_digest)
        object.__setattr__(readiness, "allows_symlinks", allows_symlinks)
        return readiness


@dataclass(frozen=True, slots=True)
class _RegularReadiness:
    state: FileObjectState
    mtime_ns: int
    digest: bytes


def _single_name(value: object, label: str) -> str:
    try:
        name = os.fspath(value)  # type: ignore[arg-type]
    except TypeError:
        raise TypeError(f"{label} must be a text path component") from None
    if not isinstance(name, str):
        raise TypeError(f"{label} must be a text path component")
    if not name or name in (".", "..") or "/" in name or "\0" in name:
        raise ValueError(f"{label} must be one non-special path component")
    return name


def _hooks(fault_hook: Hook, pause_hook: Hook) -> None:
    if not callable(fault_hook) or not callable(pause_hook):
        raise TypeError("publication hooks must be callable")


def _checkpoint(point: str, fault_hook: Hook, pause_hook: Hook) -> None:
    fault_hook(point)
    pause_hook(point)


class _PinnedObject:
    """An operation-owned duplicate descriptor and copied path bindings."""

    __slots__ = ("_source", "_fd", "_bindings", "identity", "directory_identity")

    def __init__(self, source: OpenedFile | OpenedDirectory) -> None:
        descriptor = -1
        bindings = ()
        try:
            descriptor, bindings = source._pin_for_child()
            self._validate_pin(source, descriptor, bindings)
        except (FilesystemError, PublicationError):
            if descriptor >= 0:
                filesystem._close_raw(descriptor)
            filesystem._close_bindings(list(bindings))
            raise PublicationIdentityError() from None
        self._source = source
        self._fd = descriptor
        self._bindings = bindings
        self.identity = source.identity
        self.directory_identity = (
            source.directory_identity if isinstance(source, OpenedDirectory) else None
        )

    @staticmethod
    def _validate_pin(source, descriptor: int, bindings) -> None:
        filesystem._validate_expected(
            filesystem._fstat_identity(descriptor),
            filesystem._binding_identity(source.identity),
        )
        for binding in bindings:
            current = filesystem._stat_identity_raw(binding.name, binding.parent_fd)
            if current is ABSENT:
                raise PublicationIdentityError()
            filesystem._validate_expected(current, binding.identity)

    def fileno(self) -> int:
        if self._fd < 0:
            raise PublicationIdentityError()
        return self._fd

    def recheck(self) -> None:
        if self._fd < 0:
            raise PublicationIdentityError()
        try:
            self._validate_pin(self._source, self._fd, self._bindings)
        except FilesystemError:
            raise PublicationIdentityError() from None

    def close(self) -> None:
        if self._fd < 0:
            return
        descriptor = self._fd
        bindings = self._bindings
        self._fd = -1
        self._bindings = ()
        filesystem._close_raw(descriptor)
        filesystem._close_bindings(list(bindings))


class _PinnedDirectory(_PinnedObject):
    def __init__(self, source: OpenedDirectory) -> None:
        super().__init__(source)
        assert self.directory_identity is not None

    def identity_at(self, name: str):
        try:
            result = os.stat(name, dir_fd=self.fileno(), follow_symlinks=False)
        except OSError as error:
            if error.errno == errno.ENOENT:
                return ABSENT
            raise PublicationIdentityError() from None
        try:
            return identity_from_stat(result)
        except FilesystemError:
            raise PublicationIdentityError() from None


def _pin_directory(source: OpenedDirectory) -> _PinnedDirectory:
    if not isinstance(source, OpenedDirectory):
        raise TypeError("parent must be an OpenedDirectory")
    return _PinnedDirectory(source)


def _close(fd: int) -> None:
    try:
        os.close(fd)
    except OSError:
        pass


def _stat_at(parent: _PinnedDirectory, name: str):
    try:
        return parent.identity_at(name)
    except FilesystemError:
        raise PublicationIdentityError() from None


def _fstat(fd: int) -> FileIdentity:
    try:
        return identity_from_stat(os.fstat(fd))
    except (OSError, FilesystemError):
        raise PublicationIdentityError() from None


def _same_inode(first: FileIdentity, second: FileIdentity) -> bool:
    return (
        first.dev,
        first.ino,
        first.kind,
    ) == (
        second.dev,
        second.ino,
        second.kind,
    )


def _validate_owned(identity: FileIdentity, *, kind: str | None = None) -> None:
    if (
        (kind is not None and identity.kind != kind)
        or identity.uid != os.geteuid()
        or identity.permissions & 0o022
        or (identity.kind == "regular" and identity.links != 1)
    ):
        raise PublicationPolicyError()


def _recheck_parent(parent: _PinnedDirectory) -> None:
    try:
        parent.recheck()
    except (FilesystemError, PublicationError):
        raise PublicationIdentityError() from None


def _open_exact(
    parent: _PinnedDirectory,
    name: str,
    expected: FileIdentity,
    *,
    expected_regular_links: int = 1,
) -> int:
    before = _stat_at(parent, name)
    if before is ABSENT or before != expected:
        raise PublicationIdentityError()
    assert isinstance(before, FileIdentity)
    if expected_regular_links == 1:
        _validate_owned(before)
    elif (
        before.kind != "regular"
        or before.uid != os.geteuid()
        or before.permissions & 0o022
        or before.links != expected_regular_links
    ):
        raise PublicationPolicyError()
    flags = _TREE_FILE_FLAGS if before.kind == "regular" else _TREE_DIRECTORY_FLAGS
    try:
        descriptor = os.open(name, flags, dir_fd=parent.fileno())
    except OSError:
        raise PublicationIdentityError() from None
    try:
        if os.get_inheritable(descriptor):
            raise PublicationIdentityError()
        opened = _fstat(descriptor)
        after = _stat_at(parent, name)
        if after is ABSENT or opened != expected or after != expected:
            raise PublicationIdentityError()
        _recheck_parent(parent)
    except BaseException:
        _close(descriptor)
        raise
    return descriptor


def _destination_absent(parent: _PinnedDirectory, name: str) -> None:
    try:
        current = parent.identity_at(name)
    except (FilesystemError, PublicationError):
        raise PublicationDestinationExistsError() from None
    if current is not ABSENT:
        raise PublicationDestinationExistsError()


def _load_renameat2():
    try:
        function = ctypes.CDLL(None, use_errno=True).renameat2
    except (AttributeError, OSError) as error:  # pragma: no cover - Linux/glibc contract
        raise RuntimeError("platform-pki requires Linux renameat2") from error
    function.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    function.restype = ctypes.c_int
    return function


_RENAMEAT2 = _load_renameat2()


def _renameat2(
    first_parent: _PinnedDirectory,
    first_name: str,
    second_parent: _PinnedDirectory,
    second_name: str,
    flags: int,
) -> None:
    ctypes.set_errno(0)
    result = _RENAMEAT2(
        first_parent.fileno(),
        os.fsencode(first_name),
        second_parent.fileno(),
        os.fsencode(second_name),
        flags,
    )
    if result != 0:
        code = ctypes.get_errno()
        if code in (errno.EEXIST, errno.ENOTEMPTY):
            raise PublicationDestinationExistsError()
        if code == errno.EXDEV:
            raise PublicationCrossDeviceError()
        raise PublicationMutationError()


def _sync_parent(parent: _PinnedDirectory) -> None:
    try:
        os.fsync(parent.fileno())
    except OSError:
        raise PublicationDurabilityError() from None


def _sync_parents(first: _PinnedDirectory, second: _PinnedDirectory) -> None:
    _sync_parent(first)
    assert first.directory_identity is not None
    assert second.directory_identity is not None
    if (
        first.directory_identity.dev,
        first.directory_identity.ino,
    ) != (
        second.directory_identity.dev,
        second.directory_identity.ino,
    ):
        _sync_parent(second)


def _hash_file(descriptor: int) -> bytes:
    digest = hashlib.sha256()
    offset = 0
    while True:
        try:
            chunk = os.pread(descriptor, _WRITE_CHUNK, offset)
        except OSError:
            raise PublicationIdentityError() from None
        if not chunk:
            return digest.digest()
        digest.update(chunk)
        offset += len(chunk)


def _prepare_regular_source(
    parent: _PinnedDirectory,
    name: str,
    expected: FileIdentity,
    descriptor: int,
) -> _RegularReadiness:
    try:
        os.fsync(descriptor)
    except OSError:
        raise PublicationMutationError() from None
    before = _fstat(descriptor)
    path_before = _stat_at(parent, name)
    digest = _hash_file(descriptor)
    after = _fstat(descriptor)
    path_after = _stat_at(parent, name)
    _recheck_parent(parent)
    if (
        before != expected
        or path_before != expected
        or after != expected
        or path_after != expected
    ):
        raise PublicationIdentityError()
    return _RegularReadiness(expected.state, expected.mtime_ns, digest)


def _validate_regular_observation(
    parent: _PinnedDirectory,
    name: str,
    expected_inode: FileIdentity,
    readiness: _RegularReadiness,
    descriptor: int,
) -> FileIdentity:
    path_before = _stat_at(parent, name)
    opened_before = _fstat(descriptor)
    if (
        path_before is ABSENT
        or not isinstance(path_before, FileIdentity)
        or path_before != opened_before
        or not _same_inode(path_before, expected_inode)
    ):
        raise PublicationValidationError()
    digest = _hash_file(descriptor)
    path_after = _stat_at(parent, name)
    opened_after = _fstat(descriptor)
    _recheck_parent(parent)
    if (
        path_after is ABSENT
        or not isinstance(path_after, FileIdentity)
        or path_after != opened_after
        or path_before != path_after
        or path_after.state != readiness.state
        or path_after.mtime_ns != readiness.mtime_ns
        or digest != readiness.digest
    ):
        raise PublicationValidationError()
    _validate_owned(path_after, kind="regular")
    return path_after


def _published_identity(
    source_parent: _PinnedDirectory,
    source: str,
    destination_parent: _PinnedDirectory,
    destination: str,
    expected: FileIdentity,
    descriptor: int,
    regular_readiness: _RegularReadiness | None,
    tree_readiness: TreeReadiness | None,
) -> FileIdentity:
    source_final = _stat_at(source_parent, source)
    if source_final is not ABSENT:
        raise PublicationValidationError()
    if expected.kind == "regular":
        assert regular_readiness is not None
        return _validate_regular_observation(
            destination_parent,
            destination,
            expected,
            regular_readiness,
            descriptor,
        )
    assert tree_readiness is not None
    return _validate_tree_root(
        destination_parent,
        destination,
        expected,
        tree_readiness,
        descriptor,
    )


def _exchanged_identities(
    first_parent: _PinnedDirectory,
    first: str,
    expected_first: FileIdentity,
    first_fd: int,
    second_parent: _PinnedDirectory,
    second: str,
    expected_second: FileIdentity,
    second_fd: int,
    first_regular: _RegularReadiness | None,
    second_regular: _RegularReadiness | None,
    first_tree: TreeReadiness | None,
    second_tree: TreeReadiness | None,
) -> tuple[FileIdentity, FileIdentity]:
    if expected_first.kind == "regular":
        assert first_regular is not None and second_regular is not None
        first_final = _validate_regular_observation(
            first_parent,
            first,
            expected_second,
            second_regular,
            second_fd,
        )
        second_final = _validate_regular_observation(
            second_parent,
            second,
            expected_first,
            first_regular,
            first_fd,
        )
    else:
        assert first_tree is not None and second_tree is not None
        first_final = _validate_tree_root(
            first_parent,
            first,
            expected_second,
            second_tree,
            second_fd,
        )
        second_final = _validate_tree_root(
            second_parent,
            second,
            expected_first,
            first_tree,
            first_fd,
        )
    return first_final, second_final


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    offset = 0
    try:
        while offset < len(view):
            written = os.write(descriptor, view[offset : offset + _WRITE_CHUNK])
            if written <= 0:
                raise OSError(errno.EIO, "write made no progress")
            offset += written
    finally:
        view.release()


class StagedFile:
    """An owned, open, same-parent staging file with exact path identity."""

    __slots__ = ("parent", "name", "identity", "_fd", "_consumed", "_parent_pin")

    def __init__(
        self,
        parent: OpenedDirectory,
        parent_pin: _PinnedDirectory,
        name: str,
        identity: FileIdentity,
        descriptor: int,
    ) -> None:
        self.parent = parent
        self.name = name
        self.identity = identity
        self._fd = descriptor
        self._consumed = False
        self._parent_pin = parent_pin

    def fileno(self) -> int:
        if self._fd < 0:
            raise PublicationStageError()
        return self._fd

    @property
    def consumed(self) -> bool:
        return self._consumed

    def mark_consumed(self) -> None:
        self._consumed = True

    def close(self) -> None:
        failure = False
        if self._fd >= 0:
            descriptor = self._fd
            self._fd = -1
            try:
                os.close(descriptor)
            except OSError:
                failure = True
        self._parent_pin.close()
        if failure:
            raise PublicationCleanupError()

    def cleanup(
        self,
        *,
        fault_hook: Hook = DEFAULT_FAULT_HOOK,
        pause_hook: Hook = DEFAULT_PAUSE_HOOK,
    ) -> None:
        if not self._consumed:
            _unlink_exact_pinned(
                self._parent_pin,
                self.name,
                self.identity,
                fault_hook=fault_hook,
                pause_hook=pause_hook,
            )
            self._consumed = True

    def __enter__(self) -> StagedFile:
        return self

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool:
        cleanup_error: BaseException | None = None
        try:
            self.cleanup()
        except BaseException as error:
            cleanup_error = error
        try:
            self.close()
        except BaseException as error:
            cleanup_error = cleanup_error or error
        if exception is not None:
            if cleanup_error is not None:
                raise exception from cleanup_error
            return False
        if cleanup_error is not None:
            raise cleanup_error
        return False


def stage_file_bytes(
    parent: OpenedDirectory,
    destination_name: str | os.PathLike[str],
    data: bytes,
    *,
    mode: int = 0o600,
    owner: int | None = None,
    fault_hook: Hook = DEFAULT_FAULT_HOOK,
    pause_hook: Hook = DEFAULT_PAUSE_HOOK,
) -> StagedFile:
    """Create and fully synchronize an owned stage beside its destination."""

    if not isinstance(parent, OpenedDirectory):
        raise TypeError("parent must be an OpenedDirectory")
    destination = _single_name(destination_name, "destination_name")
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if (
        isinstance(mode, bool)
        or not isinstance(mode, int)
        or not 0 <= mode <= 0o777
        or not mode & 0o400
        or mode & 0o022
    ):
        raise ValueError(
            "mode must be owner-readable without group or world write"
        )
    expected_owner = os.geteuid() if owner is None else owner
    if (
        isinstance(expected_owner, bool)
        or not isinstance(expected_owner, int)
        or expected_owner < 0
    ):
        raise ValueError("owner must be a nonnegative integer")
    if expected_owner != os.geteuid():
        raise PublicationPolicyError()
    _hooks(fault_hook, pause_hook)
    parent_pin = _pin_directory(parent)
    _recheck_parent(parent_pin)

    descriptor = -1
    name: str | None = None
    identity: FileIdentity | None = None
    try:
        _checkpoint("stage-before-create", fault_hook, pause_hook)
        _recheck_parent(parent_pin)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
        for _attempt in range(_STAGE_ATTEMPTS):
            name = f".{destination}.stage-{secrets.token_hex(16)}"
            try:
                descriptor = os.open(name, flags, mode, dir_fd=parent_pin.fileno())
            except FileExistsError:
                continue
            except OSError:
                raise PublicationStageError() from None
            break
        else:
            raise PublicationStageError()
        if os.get_inheritable(descriptor):
            raise PublicationStageError()
        os.fchmod(descriptor, mode)
        _checkpoint("stage-after-create", fault_hook, pause_hook)
        _checkpoint("stage-before-write", fault_hook, pause_hook)
        _write_all(descriptor, data)
        _checkpoint("stage-after-write", fault_hook, pause_hook)
        _checkpoint("stage-before-file-fsync", fault_hook, pause_hook)
        os.fsync(descriptor)
        _checkpoint("stage-after-file-fsync", fault_hook, pause_hook)
        identity = _fstat(descriptor)
        if (
            identity.kind != "regular"
            or identity.uid != expected_owner
            or identity.permissions != mode
            or identity.links != 1
            or identity.size != len(data)
        ):
            raise PublicationStageError()
        _checkpoint("stage-before-final-validation", fault_hook, pause_hook)
        current = _stat_at(parent_pin, name)
        _recheck_parent(parent_pin)
        if current is ABSENT or current != identity:
            raise PublicationIdentityError()
        _checkpoint("stage-after-final-validation", fault_hook, pause_hook)
        current = _stat_at(parent_pin, name)
        _recheck_parent(parent_pin)
        if current is ABSENT or current != identity or _fstat(descriptor) != identity:
            raise PublicationIdentityError()
        return StagedFile(parent, parent_pin, name, identity, descriptor)
    except BaseException as caught:
        primary = caught if isinstance(caught, ApplicationError) else PublicationStageError()
        cleanup_error: BaseException | None = None
        if descriptor >= 0 and name is not None:
            try:
                if identity is None:
                    identity = _fstat(descriptor)
                current = _stat_at(parent_pin, name)
                if current is not ABSENT and current == identity:
                    os.unlink(name, dir_fd=parent_pin.fileno())
                    os.fsync(parent_pin.fileno())
            except BaseException as cleanup:
                cleanup_error = cleanup
            _close(descriptor)
        parent_pin.close()
        if cleanup_error is not None:
            raise primary from cleanup_error
        raise primary from None


def unlink_exact(
    parent: OpenedDirectory,
    name: str | os.PathLike[str],
    expected_identity: FileIdentity,
    *,
    fault_hook: Hook = DEFAULT_FAULT_HOOK,
    pause_hook: Hook = DEFAULT_PAUSE_HOOK,
) -> None:
    """Unlink only the expected regular file and synchronize its parent.

    A competing replacement installed before the final recheck survives.  See
    the module documentation for the same-UID check/unlink limitation.
    """

    if not isinstance(parent, OpenedDirectory):
        raise TypeError("parent must be an OpenedDirectory")
    component = _single_name(name, "name")
    if not isinstance(expected_identity, FileIdentity):
        raise TypeError("expected_identity must be a FileIdentity")
    _hooks(fault_hook, pause_hook)
    if expected_identity.kind != "regular":
        raise PublicationPolicyError()
    parent_pin = _pin_directory(parent)
    try:
        _unlink_exact_pinned(
            parent_pin,
            component,
            expected_identity,
            fault_hook=fault_hook,
            pause_hook=pause_hook,
        )
    finally:
        parent_pin.close()


def _unlink_exact_pinned(
    parent: _PinnedDirectory,
    component: str,
    expected_identity: FileIdentity,
    *,
    fault_hook: Hook,
    pause_hook: Hook,
) -> None:
    descriptor = _open_exact(parent, component, expected_identity)
    mutated = False
    try:
        _checkpoint("cleanup-before-unlink", fault_hook, pause_hook)
        current = _stat_at(parent, component)
        _recheck_parent(parent)
        if current is ABSENT or current != expected_identity:
            raise PublicationIdentityError()
        try:
            os.unlink(component, dir_fd=parent.fileno())
        except OSError:
            raise PublicationCleanupError() from None
        mutated = True
        _checkpoint("cleanup-after-unlink", fault_hook, pause_hook)
        opened = _fstat(descriptor)
        if not _same_inode(opened, expected_identity) or opened.links != 0:
            raise PublicationCleanupError()
        _checkpoint("cleanup-before-parent-fsync", fault_hook, pause_hook)
        try:
            os.fsync(parent.fileno())
        except OSError:
            raise PublicationDurabilityError() from None
        _checkpoint("cleanup-after-parent-fsync", fault_hook, pause_hook)
        _recheck_parent(parent)
    except BaseException as error:
        if mutated and not isinstance(error, PublicationAmbiguousError):
            raise PublicationCleanupAmbiguousError() from error
        raise
    finally:
        _close(descriptor)


def publish_no_clobber(
    source_parent: OpenedDirectory,
    source_name: str | os.PathLike[str],
    expected_source: FileIdentity,
    destination_parent: OpenedDirectory,
    destination_name: str | os.PathLike[str],
    *,
    readiness: TreeReadiness | None = None,
    pre_publish_check: Callable[[], None] | None = None,
    fault_hook: Hook = DEFAULT_FAULT_HOOK,
    pause_hook: Hook = DEFAULT_PAUSE_HOOK,
) -> PublicationResult:
    """Atomically rename one exact file or directory to an absent destination."""

    if not isinstance(source_parent, OpenedDirectory) or not isinstance(
        destination_parent, OpenedDirectory
    ):
        raise TypeError("publication parents must be OpenedDirectory objects")
    if not isinstance(expected_source, FileIdentity):
        raise TypeError("expected_source must be a FileIdentity")
    source = _single_name(source_name, "source_name")
    destination = _single_name(destination_name, "destination_name")
    _hooks(fault_hook, pause_hook)
    if expected_source.kind == "directory" and not isinstance(readiness, TreeReadiness):
        raise PublicationPolicyError()
    if expected_source.kind == "regular" and readiness is not None:
        raise PublicationPolicyError()
    if pre_publish_check is not None and not callable(pre_publish_check):
        raise TypeError("pre_publish_check must be callable or None")

    source_pin = _pin_directory(source_parent)
    try:
        destination_pin = (
            source_pin
            if destination_parent is source_parent
            else _pin_directory(destination_parent)
        )
    except BaseException:
        source_pin.close()
        raise
    assert source_pin.directory_identity is not None
    assert destination_pin.directory_identity is not None
    if (
        source_pin.directory_identity == destination_pin.directory_identity
        and source == destination
    ):
        if destination_pin is not source_pin:
            destination_pin.close()
        source_pin.close()
        raise ValueError("source and destination names must differ")
    if (
        expected_source.dev != source_pin.directory_identity.dev
        or source_pin.directory_identity.dev != destination_pin.directory_identity.dev
    ):
        if destination_pin is not source_pin:
            destination_pin.close()
        source_pin.close()
        raise PublicationCrossDeviceError()

    descriptor = -1
    mutated = False
    try:
        descriptor = _open_exact(source_pin, source, expected_source)
        _destination_absent(destination_pin, destination)
        _recheck_parent(destination_pin)
        _checkpoint("publication-before-mutation", fault_hook, pause_hook)
        regular_readiness = None
        if expected_source.kind == "regular":
            regular_readiness = _prepare_regular_source(
                source_pin,
                source,
                expected_source,
                descriptor,
            )
        else:
            assert readiness is not None
            _validate_tree_source(
                source_pin,
                source,
                expected_source,
                readiness,
                descriptor,
            )
        _destination_absent(destination_pin, destination)
        _recheck_parent(source_pin)
        _recheck_parent(destination_pin)
        if pre_publish_check is not None:
            pre_publish_check()
            if expected_source.kind == "regular":
                if (
                    _prepare_regular_source(
                        source_pin,
                        source,
                        expected_source,
                        descriptor,
                    )
                    != regular_readiness
                ):
                    raise PublicationIdentityError()
            else:
                assert readiness is not None
                _validate_tree_source(
                    source_pin,
                    source,
                    expected_source,
                    readiness,
                    descriptor,
                )
            _destination_absent(destination_pin, destination)
            _recheck_parent(source_pin)
            _recheck_parent(destination_pin)
        _renameat2(
            source_pin,
            source,
            destination_pin,
            destination,
            _RENAME_NOREPLACE,
        )
        mutated = True
        _checkpoint("publication-after-mutation", fault_hook, pause_hook)
        _checkpoint("publication-before-parent-fsync", fault_hook, pause_hook)
        _sync_parents(source_pin, destination_pin)
        _checkpoint("publication-after-parent-fsync", fault_hook, pause_hook)
        _checkpoint("publication-before-final-validation", fault_hook, pause_hook)
        destination_final = _published_identity(
            source_pin,
            source,
            destination_pin,
            destination,
            expected_source,
            descriptor,
            regular_readiness,
            readiness,
        )
        _checkpoint("publication-after-final-validation", fault_hook, pause_hook)
        destination_final = _published_identity(
            source_pin,
            source,
            destination_pin,
            destination,
            expected_source,
            descriptor,
            regular_readiness,
            readiness,
        )
        return PublicationResult(
            destination_final,
            source_pin.directory_identity,
            destination_pin.directory_identity,
        )
    except BaseException as error:
        if mutated and not isinstance(error, PublicationAmbiguousError):
            raise PublicationValidationError() from error
        raise
    finally:
        if descriptor >= 0:
            _close(descriptor)
        if destination_pin is not source_pin:
            destination_pin.close()
        source_pin.close()


def exchange_exact(
    first_parent: OpenedDirectory,
    first_name: str | os.PathLike[str],
    expected_first: FileIdentity,
    second_parent: OpenedDirectory,
    second_name: str | os.PathLike[str],
    expected_second: FileIdentity,
    *,
    first_readiness: TreeReadiness | None = None,
    second_readiness: TreeReadiness | None = None,
    fault_hook: Hook = DEFAULT_FAULT_HOOK,
    pause_hook: Hook = DEFAULT_PAUSE_HOOK,
) -> ExchangeResult:
    """Atomically exchange two exact file-file or directory-directory names."""

    if not isinstance(first_parent, OpenedDirectory) or not isinstance(
        second_parent, OpenedDirectory
    ):
        raise TypeError("exchange parents must be OpenedDirectory objects")
    if not isinstance(expected_first, FileIdentity) or not isinstance(
        expected_second, FileIdentity
    ):
        raise TypeError("exchange identities must be FileIdentity objects")
    first = _single_name(first_name, "first_name")
    second = _single_name(second_name, "second_name")
    if expected_first.kind != expected_second.kind:
        raise PublicationPolicyError()
    if expected_first.kind == "directory" and (
        not isinstance(first_readiness, TreeReadiness)
        or not isinstance(second_readiness, TreeReadiness)
    ):
        raise PublicationPolicyError()
    if expected_first.kind == "regular" and (
        first_readiness is not None or second_readiness is not None
    ):
        raise PublicationPolicyError()
    _hooks(fault_hook, pause_hook)

    first_pin = _pin_directory(first_parent)
    try:
        second_pin = (
            first_pin
            if second_parent is first_parent
            else _pin_directory(second_parent)
        )
    except BaseException:
        first_pin.close()
        raise
    assert first_pin.directory_identity is not None
    assert second_pin.directory_identity is not None
    if first_pin.directory_identity == second_pin.directory_identity and first == second:
        if second_pin is not first_pin:
            second_pin.close()
        first_pin.close()
        raise ValueError("exchange names must differ")
    if (
        expected_first.dev != first_pin.directory_identity.dev
        or expected_second.dev != second_pin.directory_identity.dev
        or first_pin.directory_identity.dev != second_pin.directory_identity.dev
    ):
        if second_pin is not first_pin:
            second_pin.close()
        first_pin.close()
        raise PublicationCrossDeviceError()

    first_fd = -1
    second_fd = -1
    mutated = False
    try:
        first_fd = _open_exact(first_pin, first, expected_first)
        second_fd = _open_exact(second_pin, second, expected_second)
        _checkpoint("exchange-before-mutation", fault_hook, pause_hook)
        first_regular = second_regular = None
        if expected_first.kind == "regular":
            first_regular = _prepare_regular_source(
                first_pin, first, expected_first, first_fd
            )
            second_regular = _prepare_regular_source(
                second_pin, second, expected_second, second_fd
            )
        else:
            assert first_readiness is not None and second_readiness is not None
            _validate_tree_source(
                first_pin, first, expected_first, first_readiness, first_fd
            )
            _validate_tree_source(
                second_pin, second, expected_second, second_readiness, second_fd
            )
        _recheck_parent(first_pin)
        _recheck_parent(second_pin)
        _renameat2(
            first_pin,
            first,
            second_pin,
            second,
            _RENAME_EXCHANGE,
        )
        mutated = True
        _checkpoint("exchange-after-mutation", fault_hook, pause_hook)
        _checkpoint("exchange-before-parent-fsync", fault_hook, pause_hook)
        _sync_parents(first_pin, second_pin)
        _checkpoint("exchange-after-parent-fsync", fault_hook, pause_hook)
        _checkpoint("exchange-before-final-validation", fault_hook, pause_hook)
        first_final, second_final = _exchanged_identities(
            first_pin,
            first,
            expected_first,
            first_fd,
            second_pin,
            second,
            expected_second,
            second_fd,
            first_regular,
            second_regular,
            first_readiness,
            second_readiness,
        )
        _checkpoint("exchange-after-final-validation", fault_hook, pause_hook)
        first_final, second_final = _exchanged_identities(
            first_pin,
            first,
            expected_first,
            first_fd,
            second_pin,
            second,
            expected_second,
            second_fd,
            first_regular,
            second_regular,
            first_readiness,
            second_readiness,
        )
        return ExchangeResult(
            first_final,
            second_final,
            first_pin.directory_identity,
            second_pin.directory_identity,
        )
    except BaseException as error:
        if mutated and not isinstance(error, PublicationAmbiguousError):
            raise PublicationValidationError() from error
        raise
    finally:
        if second_fd >= 0:
            _close(second_fd)
        if first_fd >= 0:
            _close(first_fd)
        if second_pin is not first_pin:
            second_pin.close()
        first_pin.close()


def exchange_guarded_regular_files(
    parent: OpenedDirectory,
    stage_name: str | os.PathLike[str],
    expected_stage: FileIdentity,
    destination_name: str | os.PathLike[str],
    expected_destination: FileIdentity,
    guard_name: str | os.PathLike[str],
    expected_guard: FileIdentity,
    *,
    fault_hook: Hook = DEFAULT_FAULT_HOOK,
    pause_hook: Hook = DEFAULT_PAUSE_HOOK,
) -> ExchangeResult:
    """Exchange a stage with a destination protected by one exact hard-link guard.

    This primitive exists for the retained inventory-install publication contract.
    The destination and guard must be the same current-user-owned regular inode
    with link count two. A destination race at the exchange syscall boundary is
    exchanged back when the staged inode reached the destination; uncertainty
    after either mutation is reported as ambiguous and left untouched.
    """

    if not isinstance(parent, OpenedDirectory):
        raise TypeError("parent must be an OpenedDirectory")
    if not all(
        isinstance(identity, FileIdentity)
        for identity in (expected_stage, expected_destination, expected_guard)
    ):
        raise TypeError("guarded exchange identities must be FileIdentity objects")
    stage = _single_name(stage_name, "stage_name")
    destination = _single_name(destination_name, "destination_name")
    guard = _single_name(guard_name, "guard_name")
    if len({stage, destination, guard}) != 3:
        raise ValueError("guarded exchange names must differ")
    if (
        expected_stage.kind != "regular"
        or expected_stage.links != 1
        or expected_destination.kind != "regular"
        or expected_destination.links != 2
        or expected_guard != expected_destination
    ):
        raise PublicationPolicyError()
    _hooks(fault_hook, pause_hook)

    parent_pin = _pin_directory(parent)
    assert parent_pin.directory_identity is not None
    stage_fd = destination_fd = guard_fd = -1
    exchanged = False
    restored = False
    try:
        stage_fd = _open_exact(parent_pin, stage, expected_stage)
        destination_fd = _open_exact(
            parent_pin,
            destination,
            expected_destination,
            expected_regular_links=2,
        )
        guard_fd = _open_exact(
            parent_pin,
            guard,
            expected_guard,
            expected_regular_links=2,
        )
        if not _same_inode(_fstat(destination_fd), _fstat(guard_fd)):
            raise PublicationIdentityError()

        _checkpoint("guarded-exchange-before-mutation", fault_hook, pause_hook)
        if (
            _stat_at(parent_pin, stage) != expected_stage
            or _stat_at(parent_pin, destination) != expected_destination
            or _stat_at(parent_pin, guard) != expected_guard
        ):
            raise PublicationIdentityError()
        _recheck_parent(parent_pin)
        _renameat2(
            parent_pin,
            stage,
            parent_pin,
            destination,
            _RENAME_EXCHANGE,
        )
        exchanged = True
        _checkpoint("guarded-exchange-after-mutation", fault_hook, pause_hook)

        staged_at_destination = _stat_at(parent_pin, destination)
        displaced_at_stage = _stat_at(parent_pin, stage)
        guarded = _stat_at(parent_pin, guard)
        _recheck_parent(parent_pin)
        if (
            isinstance(staged_at_destination, FileIdentity)
            and isinstance(displaced_at_stage, FileIdentity)
            and isinstance(guarded, FileIdentity)
            and _same_inode(staged_at_destination, expected_stage)
            and _same_inode(displaced_at_stage, expected_destination)
            and _same_inode(guarded, expected_guard)
        ):
            return ExchangeResult(
                displaced_at_stage,
                staged_at_destination,
                parent_pin.directory_identity,
                parent_pin.directory_identity,
            )

        if (
            isinstance(staged_at_destination, FileIdentity)
            and isinstance(displaced_at_stage, FileIdentity)
            and _same_inode(staged_at_destination, expected_stage)
        ):
            _renameat2(
                parent_pin,
                stage,
                parent_pin,
                destination,
                _RENAME_EXCHANGE,
            )
            restored = True
            restored_stage = _stat_at(parent_pin, stage)
            restored_destination = _stat_at(parent_pin, destination)
            _recheck_parent(parent_pin)
            if (
                isinstance(restored_stage, FileIdentity)
                and isinstance(restored_destination, FileIdentity)
                and _same_inode(restored_stage, expected_stage)
                and _same_inode(restored_destination, displaced_at_stage)
            ):
                raise GuardedExchangeRaceError()
        raise PublicationValidationError()
    except BaseException as error:
        if exchanged and not restored and not isinstance(error, PublicationAmbiguousError):
            raise PublicationValidationError() from error
        raise
    finally:
        for descriptor in (guard_fd, destination_fd, stage_fd):
            if descriptor >= 0:
                _close(descriptor)
        parent_pin.close()


def _removed_at(parent_fd: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as error:
        if error.errno == errno.ENOENT:
            return True
        raise PublicationReplacementCleanupError() from None
    return False


def _remove_replaced_regular(
    parent: _PinnedDirectory,
    name: str,
    expected: FileIdentity,
    descriptor: int,
) -> None:
    current = _stat_at(parent, name)
    if current != expected or _fstat(descriptor) != expected:
        raise PublicationReplacementCleanupError()
    try:
        os.unlink(name, dir_fd=parent.fileno())
    except OSError:
        raise PublicationReplacementCleanupError() from None
    opened = _fstat(descriptor)
    if not _same_inode(opened, expected) or opened.links != 0:
        raise PublicationReplacementCleanupError()
    if not _removed_at(parent.fileno(), name):
        raise PublicationReplacementCleanupError()
    _sync_parent(parent)


def replace_exact(
    source_parent: OpenedDirectory,
    source_name: str | os.PathLike[str],
    expected_source: FileIdentity,
    destination_parent: OpenedDirectory,
    destination_name: str | os.PathLike[str],
    expected_destination: FileIdentity,
    *,
    source_readiness: TreeReadiness | None = None,
    destination_readiness: TreeReadiness | None = None,
    pre_exchange_check: Callable[[], None] | None = None,
    fault_hook: Hook = DEFAULT_FAULT_HOOK,
    pause_hook: Hook = DEFAULT_PAUSE_HOOK,
) -> ReplacementResult:
    """Replace one exact destination under cooperative locking and stage ownership.

    Both names remain untouched on failures before ``RENAME_EXCHANGE``.  Once
    exchanged, this function never attempts rollback: the new destination is
    retained and failures are reported as ambiguous. Regular displaced files
    are identity-unlinked; complete displaced directory trees remain at the
    source name for later caller-journaled cleanup. Linux provides no
    compare-and-swap exchange, and regular cleanup has the same same-UID final
    name-check limitation documented for :func:`unlink_exact`.
    """

    if not isinstance(source_parent, OpenedDirectory) or not isinstance(
        destination_parent, OpenedDirectory
    ):
        raise TypeError("replacement parents must be OpenedDirectory objects")
    if not isinstance(expected_source, FileIdentity) or not isinstance(
        expected_destination, FileIdentity
    ):
        raise TypeError("replacement identities must be FileIdentity objects")
    source = _single_name(source_name, "source_name")
    destination = _single_name(destination_name, "destination_name")
    if expected_source.kind != expected_destination.kind:
        raise PublicationPolicyError()
    if expected_source.kind == "directory" and (
        not isinstance(source_readiness, TreeReadiness)
        or not isinstance(destination_readiness, TreeReadiness)
    ):
        raise PublicationPolicyError()
    if expected_source.kind == "regular" and (
        source_readiness is not None or destination_readiness is not None
    ):
        raise PublicationPolicyError()
    if pre_exchange_check is not None and not callable(pre_exchange_check):
        raise TypeError("pre_exchange_check must be callable or None")
    _hooks(fault_hook, pause_hook)

    source_pin = _pin_directory(source_parent)
    try:
        destination_pin = (
            source_pin
            if destination_parent is source_parent
            else _pin_directory(destination_parent)
        )
    except BaseException:
        source_pin.close()
        raise
    assert source_pin.directory_identity is not None
    assert destination_pin.directory_identity is not None
    if source_pin.directory_identity == destination_pin.directory_identity and (
        source == destination
    ):
        if destination_pin is not source_pin:
            destination_pin.close()
        source_pin.close()
        raise ValueError("replacement names must differ")
    if (
        expected_source.dev != source_pin.directory_identity.dev
        or expected_destination.dev != destination_pin.directory_identity.dev
        or source_pin.directory_identity.dev != destination_pin.directory_identity.dev
    ):
        if destination_pin is not source_pin:
            destination_pin.close()
        source_pin.close()
        raise PublicationCrossDeviceError()

    source_fd = -1
    destination_fd = -1
    exchanged = False
    cleanup_started = False
    cleanup_removed = False
    try:
        source_fd = _open_exact(source_pin, source, expected_source)
        destination_fd = _open_exact(
            destination_pin, destination, expected_destination
        )
        _checkpoint("replacement-before-exchange", fault_hook, pause_hook)
        source_regular = destination_regular = None
        if expected_source.kind == "regular":
            source_regular = _prepare_regular_source(
                source_pin, source, expected_source, source_fd
            )
            destination_regular = _prepare_regular_source(
                destination_pin,
                destination,
                expected_destination,
                destination_fd,
            )
        else:
            assert source_readiness is not None and destination_readiness is not None
            _validate_tree_source(
                source_pin,
                source,
                expected_source,
                source_readiness,
                source_fd,
            )
            _validate_tree_source(
                destination_pin,
                destination,
                expected_destination,
                destination_readiness,
                destination_fd,
            )
        if (
            _stat_at(source_pin, source) != expected_source
            or _stat_at(destination_pin, destination) != expected_destination
        ):
            raise PublicationIdentityError()
        _recheck_parent(source_pin)
        _recheck_parent(destination_pin)
        _checkpoint(
            "replacement-before-final-authorization", fault_hook, pause_hook
        )
        if pre_exchange_check is not None:
            pre_exchange_check()
            if expected_source.kind == "regular":
                if (
                    _prepare_regular_source(
                        source_pin, source, expected_source, source_fd
                    )
                    != source_regular
                    or _prepare_regular_source(
                        destination_pin,
                        destination,
                        expected_destination,
                        destination_fd,
                    )
                    != destination_regular
                ):
                    raise PublicationIdentityError()
            else:
                assert source_readiness is not None
                assert destination_readiness is not None
                _validate_tree_source(
                    source_pin,
                    source,
                    expected_source,
                    source_readiness,
                    source_fd,
                )
                _validate_tree_source(
                    destination_pin,
                    destination,
                    expected_destination,
                    destination_readiness,
                    destination_fd,
                )
            if (
                _stat_at(source_pin, source) != expected_source
                or _stat_at(destination_pin, destination) != expected_destination
            ):
                raise PublicationIdentityError()
            _recheck_parent(source_pin)
            _recheck_parent(destination_pin)
        _renameat2(
            source_pin,
            source,
            destination_pin,
            destination,
            _RENAME_EXCHANGE,
        )
        exchanged = True
        _checkpoint("replacement-after-exchange", fault_hook, pause_hook)
        _sync_parents(source_pin, destination_pin)
        _checkpoint(
            "replacement-after-exchange-durability", fault_hook, pause_hook
        )
        destination_final, source_final = _exchanged_identities(
            destination_pin,
            destination,
            expected_destination,
            destination_fd,
            source_pin,
            source,
            expected_source,
            source_fd,
            destination_regular,
            source_regular,
            destination_readiness,
            source_readiness,
        )
        _checkpoint("replacement-before-old-disposition", fault_hook, pause_hook)
        destination_final, source_final = _exchanged_identities(
            destination_pin,
            destination,
            expected_destination,
            destination_fd,
            source_pin,
            source,
            expected_source,
            source_fd,
            destination_regular,
            source_regular,
            destination_readiness,
            source_readiness,
        )
        if expected_source.kind == "directory":
            _checkpoint(
                "replacement-after-old-disposition", fault_hook, pause_hook
            )
            _checkpoint("replacement-terminal-validation", fault_hook, pause_hook)
            destination_final, source_final = _exchanged_identities(
                destination_pin,
                destination,
                expected_destination,
                destination_fd,
                source_pin,
                source,
                expected_source,
                source_fd,
                destination_regular,
                source_regular,
                destination_readiness,
                source_readiness,
            )
            _recheck_parent(source_pin)
            _recheck_parent(destination_pin)
            return ReplacementResult(
                destination_final,
                source_final,
                ReplacementCleanupDisposition.RETAINED,
                destination_readiness,
                source_pin.directory_identity,
                destination_pin.directory_identity,
            )
        cleanup_started = True
        _remove_replaced_regular(
            source_pin,
            source,
            source_final,
            destination_fd,
        )
        cleanup_removed = True
        _checkpoint("replacement-after-old-disposition", fault_hook, pause_hook)
        _checkpoint("replacement-terminal-validation", fault_hook, pause_hook)
        destination_final = _published_identity(
            source_pin,
            source,
            destination_pin,
            destination,
            expected_source,
            source_fd,
            source_regular,
            source_readiness,
        )
        removed = _fstat(destination_fd)
        if not _same_inode(removed, expected_destination) or removed.links != 0:
            raise PublicationValidationError()
        _recheck_parent(source_pin)
        _recheck_parent(destination_pin)
        return ReplacementResult(
            destination_final,
            source_final,
            ReplacementCleanupDisposition.REMOVED,
            None,
            source_pin.directory_identity,
            destination_pin.directory_identity,
        )
    except BaseException as error:
        if exchanged:
            removed_observed = False
            if destination_fd >= 0:
                try:
                    removed = _fstat(destination_fd)
                    removed_observed = (
                        _same_inode(removed, expected_destination)
                        and removed.links == 0
                    )
                except PublicationError:
                    pass
            if removed_observed and not cleanup_removed:
                if isinstance(error, PublicationDurabilityError):
                    raise
                raise PublicationDurabilityError() from error
            if not isinstance(error, PublicationAmbiguousError):
                if cleanup_removed:
                    raise PublicationValidationError() from error
                if cleanup_started:
                    raise PublicationReplacementCleanupError() from error
                raise PublicationReplacementAmbiguousError() from error
        raise
    finally:
        if destination_fd >= 0:
            _close(destination_fd)
        if source_fd >= 0:
            _close(source_fd)
        if destination_pin is not source_pin:
            destination_pin.close()
        source_pin.close()


def atomic_write_bytes(
    parent: OpenedDirectory,
    destination_name: str | os.PathLike[str],
    data: bytes,
    *,
    mode: int = 0o600,
    owner: int | None = None,
    expected_destination: FileIdentity | object = ABSENT,
    fault_hook: Hook = DEFAULT_FAULT_HOOK,
    pause_hook: Hook = DEFAULT_PAUSE_HOOK,
) -> PublicationResult | ReplacementResult:
    """Write exact bytes, replacing only an explicitly expected destination."""

    if expected_destination is not ABSENT and not isinstance(
        expected_destination, FileIdentity
    ):
        raise TypeError("expected_destination must be ABSENT or a FileIdentity")

    stage = stage_file_bytes(
        parent,
        destination_name,
        data,
        mode=mode,
        owner=owner,
        fault_hook=fault_hook,
        pause_hook=pause_hook,
    )
    primary: BaseException | None = None
    try:
        if expected_destination is ABSENT:
            result = publish_no_clobber(
                parent,
                stage.name,
                stage.identity,
                parent,
                destination_name,
                fault_hook=fault_hook,
                pause_hook=pause_hook,
            )
        else:
            assert isinstance(expected_destination, FileIdentity)
            result = replace_exact(
                parent,
                stage.name,
                stage.identity,
                parent,
                destination_name,
                expected_destination,
                fault_hook=fault_hook,
                pause_hook=pause_hook,
            )
        stage.mark_consumed()
        return result
    except BaseException as error:
        primary = error
        raise
    finally:
        cleanup: BaseException | None = None
        try:
            stage.cleanup(fault_hook=fault_hook, pause_hook=pause_hook)
        except BaseException as error:
            cleanup = error
        try:
            stage.close()
        except BaseException as error:
            cleanup = cleanup or error
        if cleanup is not None:
            if primary is not None:
                raise primary from cleanup
            raise cleanup


def _tree_stat(
    parent_fd: int,
    name: str,
) -> FileIdentity | _SymlinkIdentity:
    try:
        result = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if stat.S_ISLNK(result.st_mode):
            return _symlink_identity(result)
        return identity_from_stat(result)
    except (OSError, FilesystemError):
        raise PublicationTreeError() from None


def _tree_open(
    parent_fd: int,
    entry: _TreeEntry | FileIdentity | _SymlinkIdentity,
    name: str,
) -> int:
    identity = entry.identity if isinstance(entry, _TreeEntry) else entry
    flags = _TREE_DIRECTORY_FLAGS if identity.kind == "directory" else _TREE_FILE_FLAGS
    try:
        descriptor = os.open(name, flags, dir_fd=parent_fd)
    except OSError:
        raise PublicationTreeError() from None
    try:
        if os.get_inheritable(descriptor) or _fstat(descriptor) != identity:
            raise PublicationTreeError()
    except BaseException:
        _close(descriptor)
        raise
    return descriptor


def _tree_open_symlink(
    parent_fd: int,
    name: str,
    expected: _SymlinkIdentity,
) -> int:
    try:
        descriptor = os.open(name, _TREE_SYMLINK_FLAGS, dir_fd=parent_fd)
    except OSError:
        raise PublicationTreeError() from None
    try:
        opened = _symlink_identity(os.fstat(descriptor))
        if os.get_inheritable(descriptor) or opened != expected:
            raise PublicationTreeError()
    except BaseException:
        _close(descriptor)
        raise
    return descriptor


def _scan_and_sync(
    descriptor: int,
    root_device: int,
    fault_hook: Hook,
    pause_hook: Hook,
    allow_symlinks: bool,
) -> tuple[_TreeEntry, ...]:
    try:
        names = tuple(sorted(os.listdir(descriptor)))
    except OSError:
        raise PublicationTreeError() from None
    entries: list[_TreeEntry] = []
    for name in names:
        identity = _tree_stat(descriptor, name)
        if isinstance(identity, _SymlinkIdentity):
            if not allow_symlinks or identity.uid != os.geteuid():
                raise PublicationTreeError()
            try:
                target = os.readlink(name, dir_fd=descriptor).encode(
                    errors="surrogateescape"
                )
            except OSError:
                raise PublicationTreeError() from None
            if _tree_stat(descriptor, name) != identity:
                raise PublicationTreeError()
            entries.append(_TreeEntry(name, identity, target))
            continue
        if (
            identity.dev != root_device
            or identity.uid != os.geteuid()
            or identity.permissions & 0o022
            or (identity.kind == "regular" and identity.links != 1)
        ):
            raise PublicationTreeError()
        child_fd = _tree_open(descriptor, identity, name)
        try:
            children = (
                _scan_and_sync(
                    child_fd,
                    root_device,
                    fault_hook,
                    pause_hook,
                    allow_symlinks,
                )
                if identity.kind == "directory"
                else ()
            )
            if _tree_stat(descriptor, name) != identity or _fstat(child_fd) != identity:
                raise PublicationTreeError()
            _checkpoint("tree-before-node-fsync", fault_hook, pause_hook)
            try:
                os.fsync(child_fd)
            except OSError:
                raise PublicationTreeError() from None
            _checkpoint("tree-after-node-fsync", fault_hook, pause_hook)
            digest = _hash_file(child_fd) if identity.kind == "regular" else None
            if _tree_stat(descriptor, name) != identity or _fstat(child_fd) != identity:
                raise PublicationTreeError()
            entries.append(_TreeEntry(name, identity, digest, children))
        finally:
            _close(child_fd)
    try:
        if tuple(sorted(os.listdir(descriptor))) != names:
            raise PublicationTreeError()
    except OSError:
        raise PublicationTreeError() from None
    return tuple(entries)


def _validate_tree(
    descriptor: int,
    entries: tuple[_TreeEntry, ...],
    fault_hook: Hook,
    pause_hook: Hook,
) -> None:
    try:
        if tuple(sorted(os.listdir(descriptor))) != tuple(entry.name for entry in entries):
            raise PublicationTreeError()
    except OSError:
        raise PublicationTreeError() from None
    for entry in entries:
        if _tree_stat(descriptor, entry.name) != entry.identity:
            raise PublicationTreeError()
        if isinstance(entry.identity, _SymlinkIdentity):
            try:
                target = os.readlink(entry.name, dir_fd=descriptor).encode(
                    errors="surrogateescape"
                )
            except OSError:
                raise PublicationTreeError() from None
            if target != entry.digest or _tree_stat(descriptor, entry.name) != entry.identity:
                raise PublicationTreeError()
            continue
        child_fd = _tree_open(descriptor, entry, entry.name)
        try:
            if entry.identity.kind == "directory":
                _validate_tree(child_fd, entry.children, fault_hook, pause_hook)
            elif _hash_file(child_fd) != entry.digest:
                raise PublicationTreeError()
            if _fstat(child_fd) != entry.identity:
                raise PublicationTreeError()
            _checkpoint(
                "tree-before-child-final-name-check", fault_hook, pause_hook
            )
            if _tree_stat(descriptor, entry.name) != entry.identity:
                raise PublicationTreeError()
            _checkpoint("tree-after-child-final-name-check", fault_hook, pause_hook)
            if (
                _tree_stat(descriptor, entry.name) != entry.identity
                or _fstat(child_fd) != entry.identity
            ):
                raise PublicationTreeError()
        finally:
            _close(child_fd)


def _validate_tree_source(
    parent: _PinnedDirectory,
    name: str,
    expected: FileIdentity,
    readiness: TreeReadiness,
    descriptor: int,
) -> None:
    assert parent.directory_identity is not None
    current = _stat_at(parent, name)
    opened = _fstat(descriptor)
    if (
        readiness.root_identity != expected
        or readiness.parent_identity != parent.directory_identity
        or readiness.root_name != name
        or current != expected
        or opened != expected
    ):
        raise PublicationIdentityError()
    _validate_tree(
        descriptor,
        readiness.snapshot,
        DEFAULT_FAULT_HOOK,
        DEFAULT_PAUSE_HOOK,
    )
    if _stat_at(parent, name) != expected or _fstat(descriptor) != expected:
        raise PublicationIdentityError()
    _recheck_parent(parent)


def _validate_tree_root(
    parent: _PinnedDirectory,
    name: str,
    expected_inode: FileIdentity,
    readiness: TreeReadiness,
    descriptor: int,
) -> FileIdentity:
    path_before = _stat_at(parent, name)
    opened_before = _fstat(descriptor)
    if (
        path_before is ABSENT
        or not isinstance(path_before, FileIdentity)
        or path_before != opened_before
        or not _same_inode(path_before, expected_inode)
        or path_before.state != readiness.root_identity.state
        or path_before.mtime_ns != readiness.root_identity.mtime_ns
    ):
        raise PublicationValidationError()
    _validate_tree(
        descriptor,
        readiness.snapshot,
        DEFAULT_FAULT_HOOK,
        DEFAULT_PAUSE_HOOK,
    )
    path_after = _stat_at(parent, name)
    opened_after = _fstat(descriptor)
    _recheck_parent(parent)
    if (
        path_after is ABSENT
        or not isinstance(path_after, FileIdentity)
        or path_after != opened_after
        or path_before != path_after
        or path_after.state != readiness.root_identity.state
        or path_after.mtime_ns != readiness.root_identity.mtime_ns
    ):
        raise PublicationValidationError()
    _validate_owned(path_after, kind="directory")
    return path_after


def fsync_tree(
    root: OpenedFile | OpenedDirectory,
    publication_parent: OpenedDirectory,
    root_name: str | os.PathLike[str],
    *,
    fault_hook: Hook = DEFAULT_FAULT_HOOK,
    pause_hook: Hook = DEFAULT_PAUSE_HOOK,
    allow_symlinks: bool = False,
) -> TreeReadiness:
    """Synchronize one already-opened, same-filesystem regular/directory tree.

    Traversal is descriptor-relative and no-follow.  It rejects policy changes
    observed before final validation, but does not freeze a writable tree against
    a hostile same-UID process after the final check; callers must hold the
    cooperative lifecycle lock and exclusive ownership of staged names.
    """

    if not isinstance(root, (OpenedFile, OpenedDirectory)) or not isinstance(
        publication_parent, OpenedDirectory
    ):
        raise TypeError(
            "tree root must be an opened file or directory and publication parent "
            "must be an OpenedDirectory"
        )
    name = _single_name(root_name, "root_name")
    if not isinstance(allow_symlinks, bool):
        raise TypeError("allow_symlinks must be a boolean")
    _hooks(fault_hook, pause_hook)
    root_pin = (
        _pin_directory(root)
        if isinstance(root, OpenedDirectory)
        else _PinnedObject(root)
    )
    try:
        parent_pin = (
            root_pin
            if publication_parent is root
            else _pin_directory(publication_parent)
        )
    except BaseException:
        root_pin.close()
        raise
    assert isinstance(parent_pin, _PinnedDirectory)
    try:
        root_identity = root_pin.identity
        assert parent_pin.directory_identity is not None
        if root_identity.dev != parent_pin.directory_identity.dev:
            raise PublicationCrossDeviceError()
        try:
            _validate_owned(root_identity, kind=root_identity.kind)
        except PublicationError:
            raise PublicationTreeError() from None
        if (
            _stat_at(parent_pin, name) != root_identity
            or _fstat(root_pin.fileno()) != root_identity
        ):
            raise PublicationTreeError()

        entries = (
            _scan_and_sync(
                root_pin.fileno(),
                root_identity.dev,
                fault_hook,
                pause_hook,
                allow_symlinks,
            )
            if isinstance(root, OpenedDirectory)
            else ()
        )
        _checkpoint("tree-before-node-fsync", fault_hook, pause_hook)
        try:
            os.fsync(root_pin.fileno())
        except OSError:
            raise PublicationTreeError() from None
        _checkpoint("tree-after-node-fsync", fault_hook, pause_hook)
        root_digest = (
            _hash_file(root_pin.fileno()) if isinstance(root, OpenedFile) else None
        )
        _checkpoint("tree-before-parent-fsync", fault_hook, pause_hook)
        try:
            os.fsync(parent_pin.fileno())
        except OSError:
            raise PublicationTreeError() from None
        _checkpoint("tree-after-parent-fsync", fault_hook, pause_hook)
        readiness = TreeReadiness._create(
            root_identity,
            parent_pin.directory_identity,
            name,
            entries,
            root_digest,
            allow_symlinks,
        )
        for point in (
            "tree-before-final-validation",
            "tree-after-final-validation",
        ):
            _checkpoint(point, fault_hook, pause_hook)
            if isinstance(root, OpenedDirectory):
                _validate_tree(root_pin.fileno(), entries, fault_hook, pause_hook)
            elif _hash_file(root_pin.fileno()) != root_digest:
                raise PublicationTreeError()
            if (
                _stat_at(parent_pin, name) != root_identity
                or _fstat(root_pin.fileno()) != root_identity
            ):
                raise PublicationTreeError()
            root_pin.recheck()
            _recheck_parent(parent_pin)
        return readiness
    finally:
        if parent_pin is not root_pin:
            parent_pin.close()
        root_pin.close()


def _remove_tree_entries(
    descriptor: int,
    entries: tuple[_TreeEntry, ...],
    fault_hook: Hook,
    pause_hook: Hook,
) -> None:
    for entry in entries:
        current = _tree_stat(descriptor, entry.name)
        if current != entry.identity:
            raise PublicationTreeCleanupError()
        if isinstance(entry.identity, _SymlinkIdentity) or entry.identity.kind == "regular":
            entry_fd = -1
            try:
                if isinstance(entry.identity, _SymlinkIdentity):
                    entry_fd = _tree_open_symlink(
                        descriptor, entry.name, entry.identity
                    )
                else:
                    entry_fd = _tree_open(descriptor, entry, entry.name)
                _checkpoint(
                    "tree-cleanup-before-entry-unlink", fault_hook, pause_hook
                )
                if _tree_stat(descriptor, entry.name) != entry.identity:
                    raise PublicationTreeCleanupError()
                if isinstance(entry.identity, _SymlinkIdentity):
                    if _symlink_identity(os.fstat(entry_fd)) != entry.identity:
                        raise PublicationTreeCleanupError()
                elif _fstat(entry_fd) != entry.identity:
                    raise PublicationTreeCleanupError()
                try:
                    os.unlink(entry.name, dir_fd=descriptor)
                except OSError:
                    raise PublicationTreeCleanupError() from None
                if not _removed_at(descriptor, entry.name):
                    raise PublicationTreeCleanupError()
                if isinstance(entry.identity, _SymlinkIdentity):
                    opened_link = _symlink_identity(os.fstat(entry_fd))
                    if (
                        not _same_symlink_inode(opened_link, entry.identity)
                        or opened_link.links != 0
                    ):
                        raise PublicationTreeCleanupError()
                else:
                    opened = _fstat(entry_fd)
                    if not _same_inode(opened, entry.identity) or opened.links != 0:
                        raise PublicationTreeCleanupError()
            finally:
                if entry_fd >= 0:
                    _close(entry_fd)
            continue

        child_fd = _tree_open(descriptor, entry, entry.name)
        try:
            _remove_tree_entries(child_fd, entry.children, fault_hook, pause_hook)
            try:
                os.fsync(child_fd)
            except OSError:
                raise PublicationTreeCleanupError() from None
            _checkpoint(
                "tree-cleanup-before-directory-rmdir", fault_hook, pause_hook
            )
            current = _tree_stat(descriptor, entry.name)
            if not isinstance(current, FileIdentity) or not _same_inode(
                current, entry.identity
            ) or not _same_inode(_fstat(child_fd), entry.identity):
                raise PublicationTreeCleanupError()
            try:
                os.rmdir(entry.name, dir_fd=descriptor)
            except OSError:
                raise PublicationTreeCleanupError() from None
            opened = _fstat(child_fd)
            if not _same_inode(opened, entry.identity) or opened.links != 0:
                raise PublicationTreeCleanupError()
            if not _removed_at(descriptor, entry.name):
                raise PublicationTreeCleanupError()
        finally:
            _close(child_fd)


def remove_exact_tree(
    parent: OpenedDirectory,
    name: str | os.PathLike[str],
    expected_identity: FileIdentity,
    readiness: TreeReadiness,
    *,
    fault_hook: Hook = DEFAULT_FAULT_HOOK,
    pause_hook: Hook = DEFAULT_PAUSE_HOOK,
) -> None:
    """Remove only one exact readiness-bound directory tree without following links."""

    if not isinstance(parent, OpenedDirectory):
        raise TypeError("parent must be an OpenedDirectory")
    component = _single_name(name, "name")
    if (
        not isinstance(expected_identity, FileIdentity)
        or expected_identity.kind != "directory"
        or not isinstance(readiness, TreeReadiness)
        or not _same_inode(readiness.root_identity, expected_identity)
        or readiness.root_identity.state != expected_identity.state
        or readiness.root_identity.mtime_ns != expected_identity.mtime_ns
    ):
        raise PublicationPolicyError()
    _hooks(fault_hook, pause_hook)
    parent_pin = _pin_directory(parent)
    descriptor = -1
    try:
        if parent_pin.directory_identity != readiness.parent_identity:
            raise PublicationTreeCleanupError()
        descriptor = _open_exact(parent_pin, component, expected_identity)
        _validate_tree_root(
            parent_pin,
            component,
            expected_identity,
            readiness,
            descriptor,
        )
        _checkpoint("tree-cleanup-before-mutation", fault_hook, pause_hook)
        _remove_tree_entries(
            descriptor,
            readiness.snapshot,
            fault_hook,
            pause_hook,
        )
        try:
            os.fsync(descriptor)
        except OSError:
            raise PublicationTreeCleanupError() from None
        _checkpoint("tree-cleanup-before-root-rmdir", fault_hook, pause_hook)
        current = _stat_at(parent_pin, component)
        if not isinstance(current, FileIdentity) or not _same_inode(
            current, expected_identity
        ) or not _same_inode(_fstat(descriptor), expected_identity):
            raise PublicationTreeCleanupError()
        try:
            os.rmdir(component, dir_fd=parent_pin.fileno())
        except OSError:
            raise PublicationTreeCleanupError() from None
        opened = _fstat(descriptor)
        if not _same_inode(opened, expected_identity) or opened.links != 0:
            raise PublicationTreeCleanupError()
        if not _removed_at(parent_pin.fileno(), component):
            raise PublicationTreeCleanupError()
        _checkpoint("tree-cleanup-after-mutation", fault_hook, pause_hook)
        _checkpoint("tree-cleanup-before-parent-fsync", fault_hook, pause_hook)
        try:
            os.fsync(parent_pin.fileno())
        except OSError:
            raise PublicationDurabilityError() from None
        _checkpoint("tree-cleanup-after-parent-fsync", fault_hook, pause_hook)
        _recheck_parent(parent_pin)
    except BaseException as error:
        if isinstance(error, PublicationTreeCleanupError):
            raise
        raise PublicationTreeCleanupError() from error
    finally:
        if descriptor >= 0:
            _close(descriptor)
        parent_pin.close()
