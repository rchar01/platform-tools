"""Descriptor-oriented filesystem validation and durability primitives."""

from __future__ import annotations

import errno
import os
import stat
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from enum import Enum
from threading import RLock
from types import TracebackType
from typing import Literal

from .errors import ApplicationError


try:
    _O_NOFOLLOW = os.O_NOFOLLOW
    _O_CLOEXEC = os.O_CLOEXEC
    _O_DIRECTORY = os.O_DIRECTORY
except AttributeError as error:  # pragma: no cover - the supported runtime is Linux
    raise RuntimeError("platform-pki requires Linux descriptor flags") from error


FileKind = Literal["regular", "directory"]
_DIRECTORY_FLAGS = os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC
_FILE_FLAGS = os.O_RDONLY | _O_NOFOLLOW | _O_CLOEXEC
_READ_CHUNK = 64 * 1024


class FilesystemError(ApplicationError):
    """A filesystem failure safe to render without disclosing a path."""


class FilesystemLookupError(FilesystemError):
    def __init__(self) -> None:
        super().__init__("Filesystem object could not be inspected")


class FilesystemAbsentError(FilesystemError):
    def __init__(self) -> None:
        super().__init__("Filesystem object is absent")


class FilesystemSymlinkError(FilesystemError):
    def __init__(self) -> None:
        super().__init__("Filesystem symbolic links are not allowed")


class FilesystemTypeError(FilesystemError):
    def __init__(self) -> None:
        super().__init__("Filesystem object has an unsupported type")


class FilesystemOpenError(FilesystemError):
    def __init__(self) -> None:
        super().__init__("Filesystem object could not be opened")


class FilesystemIdentityError(FilesystemError):
    def __init__(self) -> None:
        super().__init__("Filesystem object identity changed")


class FilesystemPolicyError(FilesystemError):
    def __init__(self) -> None:
        super().__init__("Filesystem object does not satisfy its policy")


class FilesystemClosedError(FilesystemError):
    def __init__(self) -> None:
        super().__init__("Filesystem descriptor is closed")


class FilesystemCloseError(FilesystemError):
    def __init__(self) -> None:
        super().__init__("Filesystem descriptor could not be closed")


class FilesystemReadError(FilesystemError):
    def __init__(self) -> None:
        super().__init__("Filesystem file could not be read")


class FilesystemReadLimitError(FilesystemError):
    def __init__(self) -> None:
        super().__init__("Filesystem file exceeds its read limit")


class FilesystemTraversalError(FilesystemError):
    def __init__(self) -> None:
        super().__init__("Filesystem tree could not be enumerated")


class FilesystemSyncError(FilesystemError):
    def __init__(self) -> None:
        super().__init__("Filesystem object could not be synchronized")


class TrustedAncestorError(FilesystemError):
    def __init__(self) -> None:
        super().__init__("Filesystem ancestor is not trusted")


class _Absent(Enum):
    ABSENT = "absent"

    def __repr__(self) -> str:
        return "ABSENT"


ABSENT = _Absent.ABSENT


@dataclass(frozen=True, slots=True)
class FileIdentity:
    """An exact supported-object snapshot, including nanosecond change times."""

    dev: int
    ino: int
    uid: int
    permissions: int
    links: int
    size: int
    mtime_ns: int
    ctime_ns: int
    kind: FileKind

    @property
    def state(self) -> FileObjectState:
        return FileObjectState(
            dev=self.dev,
            ino=self.ino,
            uid=self.uid,
            permissions=self.permissions,
            links=self.links,
            size=self.size,
            kind=self.kind,
        )

    @property
    def directory(self) -> DirectoryIdentity:
        if self.kind != "directory":
            raise ValueError("file identity does not describe a directory")
        return DirectoryIdentity(
            self.dev,
            self.ino,
            self.uid,
            self.permissions,
            self.kind,
        )


@dataclass(frozen=True, slots=True)
class FileObjectState:
    """A supported-object identity profile without mutable timestamps."""

    dev: int
    ino: int
    uid: int
    permissions: int
    links: int
    size: int
    kind: FileKind


@dataclass(frozen=True, slots=True)
class DirectoryIdentity:
    """The Bash-compatible identity used to recognize a directory."""

    dev: int
    ino: int
    uid: int
    permissions: int
    kind: Literal["directory"]


@dataclass(frozen=True, slots=True)
class MetadataEntry:
    """Metadata for one descriptor-relative tree entry without content."""

    relative: tuple[str, ...]
    dev: int
    ino: int
    uid: int
    permissions: int
    links: int
    size: int
    mtime_ns: int
    ctime_ns: int
    kind: str


def _policy_integer(
    value: object,
    name: str,
    *,
    minimum: int,
    maximum: int | None = None,
) -> None:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < minimum
        or (maximum is not None and value > maximum)
    ):
        qualifier = "nonnegative" if minimum == 0 else "positive"
        raise ValueError(f"{name} must be a {qualifier} integer")


@dataclass(frozen=True, slots=True)
class FilePolicy:
    """Optional exact and negative constraints for a regular file."""

    owner: int | None = None
    mode: int | None = None
    forbidden_bits: int = 0
    links: int | None = None
    max_size: int | None = None

    def __post_init__(self) -> None:
        _validate_policy_fields(self)

    def validate(self, identity: FileIdentity) -> None:
        _validate_policy(identity, self, "regular")


@dataclass(frozen=True, slots=True)
class DirectoryPolicy:
    """Optional exact and negative constraints for a directory."""

    owner: int | None = None
    mode: int | None = None
    forbidden_bits: int = 0
    links: int | None = None
    max_size: int | None = None

    def __post_init__(self) -> None:
        _validate_policy_fields(self)

    def validate(self, identity: FileIdentity) -> None:
        _validate_policy(identity, self, "directory")


def _validate_policy_fields(policy: FilePolicy | DirectoryPolicy) -> None:
    if policy.owner is not None:
        _policy_integer(policy.owner, "owner", minimum=0)
    if policy.mode is not None:
        _policy_integer(policy.mode, "mode", minimum=0, maximum=0o7777)
    _policy_integer(
        policy.forbidden_bits,
        "forbidden_bits",
        minimum=0,
        maximum=0o7777,
    )
    if policy.links is not None:
        _policy_integer(policy.links, "links", minimum=1)
    if policy.max_size is not None:
        _policy_integer(policy.max_size, "max_size", minimum=0)


def _validate_policy(
    identity: FileIdentity,
    policy: FilePolicy | DirectoryPolicy,
    kind: FileKind,
) -> None:
    if (
        identity.kind != kind
        or (policy.owner is not None and identity.uid != policy.owner)
        or (policy.mode is not None and identity.permissions != policy.mode)
        or identity.permissions & policy.forbidden_bits
        or (policy.links is not None and identity.links != policy.links)
        or (policy.max_size is not None and identity.size > policy.max_size)
    ):
        raise FilesystemPolicyError()


def identity_from_stat(result: os.stat_result) -> FileIdentity:
    """Build an exact identity from ``lstat`` or ``fstat`` output."""

    mode = result.st_mode
    if stat.S_ISREG(mode):
        kind: FileKind = "regular"
    elif stat.S_ISDIR(mode):
        kind = "directory"
    elif stat.S_ISLNK(mode):
        raise FilesystemSymlinkError()
    else:
        raise FilesystemTypeError()
    return FileIdentity(
        dev=result.st_dev,
        ino=result.st_ino,
        uid=result.st_uid,
        permissions=stat.S_IMODE(mode),
        links=result.st_nlink,
        size=result.st_size,
        mtime_ns=result.st_mtime_ns,
        ctime_ns=result.st_ctime_ns,
        kind=kind,
    )


def _path_text(path: os.PathLike[str] | str) -> str:
    try:
        value = os.fspath(path)
    except TypeError:
        raise TypeError("path must be text or a text path-like object") from None
    if not isinstance(value, str):
        raise TypeError("path must be text or a text path-like object")
    if not value or "\0" in value:
        raise ValueError("path must be nonempty and contain no NUL bytes")
    return value


def _single_name(name: os.PathLike[str] | str) -> str:
    value = _path_text(name)
    if value in (".", "..") or "/" in value:
        raise ValueError("child name must be one non-special path component")
    return value


def _split_path(path: os.PathLike[str] | str) -> tuple[str, tuple[str, ...]]:
    value = _path_text(path)
    base = "/" if value.startswith("/") else "."
    components: list[str] = []
    for component in value.split("/"):
        if component in ("", "."):
            continue
        if component == "..":
            raise ValueError("path must not contain parent traversal")
        components.append(component)
    return base, tuple(components)


def _stat_identity_raw(
    path: str,
    dir_fd: int | None,
) -> FileIdentity | _Absent:
    failure = 0
    result: os.stat_result | None = None
    try:
        result = os.stat(path, dir_fd=dir_fd, follow_symlinks=False)
    except OSError as error:
        failure = error.errno or -1
    if failure == errno.ENOENT:
        return ABSENT
    if failure:
        raise FilesystemLookupError()
    assert result is not None
    return identity_from_stat(result)


def _fstat_identity(fd: int) -> FileIdentity:
    failed = False
    result: os.stat_result | None = None
    try:
        result = os.fstat(fd)
    except OSError:
        failed = True
    if failed:
        raise FilesystemLookupError()
    assert result is not None
    return identity_from_stat(result)


def _close_raw(fd: int) -> bool:
    try:
        os.close(fd)
    except OSError:
        return False
    return True


def _open_os(path: str, flags: int, dir_fd: int | None = None) -> int:
    failed = False
    descriptor = -1
    try:
        descriptor = os.open(path, flags, dir_fd=dir_fd)
    except OSError:
        failed = True
    if failed:
        raise FilesystemOpenError()
    inheritable = True
    try:
        inheritable = os.get_inheritable(descriptor)
    except OSError:
        failed = True
    if failed or inheritable:
        _close_raw(descriptor)
        raise FilesystemOpenError()
    return descriptor


def _duplicate_fd(fd: int) -> int:
    failed = False
    duplicate = -1
    try:
        duplicate = os.dup(fd)
    except OSError:
        failed = True
    if failed:
        raise FilesystemOpenError()
    inheritable = True
    try:
        inheritable = os.get_inheritable(duplicate)
    except OSError:
        failed = True
    if failed or inheritable:
        _close_raw(duplicate)
        raise FilesystemOpenError()
    return duplicate


def _bound_open_at(
    parent_fd: int,
    name: str,
    kind: FileKind,
) -> tuple[int, FileIdentity]:
    before = _stat_identity_raw(name, parent_fd)
    if before is ABSENT:
        raise FilesystemAbsentError()
    assert isinstance(before, FileIdentity)
    if before.kind != kind:
        raise FilesystemTypeError()

    descriptor = _open_os(
        name,
        _FILE_FLAGS if kind == "regular" else _DIRECTORY_FLAGS,
        parent_fd,
    )
    try:
        opened = _fstat_identity(descriptor)
        after = _stat_identity_raw(name, parent_fd)
        if after is ABSENT or before != opened or opened != after:
            raise FilesystemIdentityError()
    except BaseException:
        _close_raw(descriptor)
        raise
    return descriptor, opened


def _bound_open_direct(path: str, kind: FileKind) -> tuple[int, FileIdentity]:
    before = _stat_identity_raw(path, None)
    if before is ABSENT:
        raise FilesystemAbsentError()
    assert isinstance(before, FileIdentity)
    if before.kind != kind:
        raise FilesystemTypeError()
    descriptor = _open_os(
        path,
        _FILE_FLAGS if kind == "regular" else _DIRECTORY_FLAGS,
    )
    try:
        opened = _fstat_identity(descriptor)
        after = _stat_identity_raw(path, None)
        if after is ABSENT or before != opened or opened != after:
            raise FilesystemIdentityError()
    except BaseException:
        _close_raw(descriptor)
        raise
    return descriptor, opened


@dataclass(frozen=True, slots=True)
class _PathBinding:
    parent_fd: int
    name: str
    identity: FileIdentity | DirectoryIdentity


def _close_bindings(bindings: list[_PathBinding]) -> bool:
    closed = True
    for binding in reversed(bindings):
        if not _close_raw(binding.parent_fd):
            closed = False
    return closed


def _copy_bindings(bindings: tuple[_PathBinding, ...]) -> list[_PathBinding]:
    copies: list[_PathBinding] = []
    try:
        for binding in bindings:
            copies.append(
                _PathBinding(
                    _duplicate_fd(binding.parent_fd),
                    binding.name,
                    binding.identity,
                )
            )
    except BaseException:
        _close_bindings(copies)
        raise
    return copies


def _binding_identity(identity: FileIdentity) -> FileIdentity | DirectoryIdentity:
    return identity.directory if identity.kind == "directory" else identity


def _open_resolved(
    path: os.PathLike[str] | str,
    kind: FileKind,
    dir_fd: int | None,
    inherited_bindings: tuple[_PathBinding, ...],
) -> tuple[int, FileIdentity, tuple[_PathBinding, ...]]:
    bindings = _copy_bindings(inherited_bindings)
    if dir_fd is not None:
        name = _single_name(path)
        parent = -1
        try:
            parent = _duplicate_fd(dir_fd)
            if _fstat_identity(parent).kind != "directory":
                raise FilesystemTypeError()
            descriptor, identity = _bound_open_at(parent, name, kind)
        except BaseException:
            if parent >= 0:
                _close_raw(parent)
            _close_bindings(bindings)
            raise
        bindings.append(_PathBinding(parent, name, _binding_identity(identity)))
        return descriptor, identity, tuple(bindings)

    base, components = _split_path(path)
    try:
        current, current_identity = _bound_open_direct(base, "directory")
    except BaseException:
        _close_bindings(bindings)
        raise
    if not components:
        if kind != "directory":
            _close_raw(current)
            _close_bindings(bindings)
            raise FilesystemTypeError()
        return current, current_identity, tuple(bindings)

    try:
        identity = current_identity
        for index, component in enumerate(components):
            final = index == len(components) - 1
            component_kind = kind if final else "directory"
            next_fd, identity = _bound_open_at(current, component, component_kind)
            bindings.append(
                _PathBinding(current, component, _binding_identity(identity))
            )
            current = next_fd
        return current, identity, tuple(bindings)
    except BaseException:
        _close_raw(current)
        _close_bindings(bindings)
        raise


def identity_at(
    path: os.PathLike[str] | str,
    *,
    dir_fd: OpenedDirectory | None = None,
) -> FileIdentity | _Absent:
    """Return an exact no-follow identity or the explicit ``ABSENT`` sentinel."""

    if dir_fd is not None:
        if not isinstance(dir_fd, OpenedDirectory):
            raise TypeError("dir_fd must be an OpenedDirectory")
        descriptor, bindings = dir_fd._pin_for_child()
        try:
            if _fstat_identity(descriptor).kind != "directory":
                raise FilesystemTypeError()
            dir_fd._recheck_pinned(descriptor, bindings)
            identity = _stat_identity_raw(_single_name(path), descriptor)
            dir_fd._recheck_pinned(descriptor, bindings)
            return identity
        finally:
            _close_raw(descriptor)
            _close_bindings(list(bindings))

    base, components = _split_path(path)
    if not components:
        return _stat_identity_raw(base, None)
    current, _identity = _bound_open_direct(base, "directory")
    try:
        for component in components[:-1]:
            next_fd, _identity = _bound_open_at(current, component, "directory")
            previous = current
            current = -1
            if not _close_raw(previous):
                _close_raw(next_fd)
                raise FilesystemCloseError()
            current = next_fd
        return _stat_identity_raw(components[-1], current)
    finally:
        if current >= 0:
            _close_raw(current)


ExpectedIdentity = FileIdentity | FileObjectState | DirectoryIdentity


def _validate_expected(actual: FileIdentity, expected: ExpectedIdentity | None) -> None:
    if expected is None:
        return
    if isinstance(expected, FileIdentity):
        matches = actual == expected
    elif isinstance(expected, FileObjectState):
        matches = actual.state == expected
    elif isinstance(expected, DirectoryIdentity):
        matches = actual.kind == "directory" and actual.directory == expected
    else:
        raise TypeError("expected_identity has an unsupported profile type")
    if not matches:
        raise FilesystemIdentityError()


class _OpenedObject:
    _kind: FileKind

    def __init__(
        self,
        path: os.PathLike[str] | str,
        *,
        policy: FilePolicy | DirectoryPolicy,
        expected_identity: ExpectedIdentity | None,
        dir_fd: OpenedDirectory | None,
    ) -> None:
        if dir_fd is not None and not isinstance(dir_fd, OpenedDirectory):
            raise TypeError("dir_fd must be an OpenedDirectory")
        pinned_fd = None
        pinned_bindings: tuple[_PathBinding, ...] = ()
        if dir_fd is not None:
            pinned_fd, pinned_bindings = dir_fd._pin_for_child()
        try:
            descriptor, identity, bindings = _open_resolved(
                path,
                self._kind,
                pinned_fd,
                pinned_bindings,
            )
        finally:
            if pinned_fd is not None:
                _close_raw(pinned_fd)
            _close_bindings(list(pinned_bindings))
        try:
            policy.validate(identity)
            _validate_expected(identity, expected_identity)
        except BaseException:
            _close_raw(descriptor)
            _close_bindings(list(bindings))
            raise
        self._fd = descriptor
        self._bindings = bindings
        self.identity = identity
        self.state = identity.state
        self._lock = RLock()

    def __enter__(self):
        if self._fd < 0:
            raise FilesystemClosedError()
        return self

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool:
        try:
            self.close()
        except FilesystemCloseError:
            if exception_type is None:
                raise
        return False

    def fileno(self) -> int:
        with self._lock:
            if self._fd < 0:
                raise FilesystemClosedError()
            return self._fd

    @property
    def closed(self) -> bool:
        return self._fd < 0

    def close(self) -> None:
        with self._lock:
            if self._fd < 0:
                return
            descriptor = self._fd
            bindings = self._bindings
            self._fd = -1
            self._bindings = ()
            failed = not _close_raw(descriptor)
            if not _close_bindings(list(bindings)):
                failed = True
            if failed:
                raise FilesystemCloseError()

    def _pin_for_child(self) -> tuple[int, tuple[_PathBinding, ...]]:
        with self._lock:
            if self._fd < 0:
                raise FilesystemClosedError()
            descriptor = _duplicate_fd(self._fd)
            try:
                bindings = tuple(_copy_bindings(self._bindings))
            except BaseException:
                _close_raw(descriptor)
                raise
            return descriptor, bindings

    def _recheck_pinned(
        self,
        descriptor: int,
        bindings: tuple[_PathBinding, ...],
    ) -> None:
        _validate_expected(_fstat_identity(descriptor), self.identity.directory)
        for binding in bindings:
            path_identity = _stat_identity_raw(binding.name, binding.parent_fd)
            if path_identity is ABSENT:
                raise FilesystemIdentityError()
            _validate_expected(path_identity, binding.identity)

    def recheck(self) -> FileIdentity:
        descriptor = self.fileno()
        current = _fstat_identity(descriptor)
        _validate_expected(current, _binding_identity(self.identity))
        for binding in self._bindings:
            path_identity = _stat_identity_raw(binding.name, binding.parent_fd)
            if path_identity is ABSENT:
                raise FilesystemIdentityError()
            _validate_expected(path_identity, binding.identity)
        return current


class OpenedFile(_OpenedObject):
    """A validated regular file and its pinned path binding."""

    _kind: FileKind = "regular"

    def __init__(
        self,
        path: os.PathLike[str] | str,
        *,
        policy: FilePolicy | None = None,
        expected_identity: ExpectedIdentity | None = None,
        dir_fd: OpenedDirectory | None = None,
    ) -> None:
        if policy is not None and not isinstance(policy, FilePolicy):
            raise TypeError("file policy must be a FilePolicy")
        super().__init__(
            path,
            policy=policy or FilePolicy(),
            expected_identity=expected_identity,
            dir_fd=dir_fd,
        )

    def read(self, max_bytes: int) -> bytes:
        """Read at most ``max_bytes + 1`` bytes and reject overflow."""

        _policy_integer(max_bytes, "max_bytes", minimum=0)
        descriptor = self.fileno()
        data = bytearray()
        offset = 0
        failed = False
        while len(data) <= max_bytes:
            request = min(_READ_CHUNK, max_bytes + 1 - len(data))
            try:
                chunk = os.pread(descriptor, request, offset)
            except OSError:
                failed = True
                break
            if not chunk:
                break
            data.extend(chunk)
            offset += len(chunk)
        if failed:
            raise FilesystemReadError()
        if len(data) > max_bytes:
            raise FilesystemReadLimitError()
        self.recheck()
        return bytes(data)

    def read_prefix(self, max_bytes: int) -> bytes:
        """Read no more than ``max_bytes`` from offset zero and recheck identity."""

        _policy_integer(max_bytes, "max_bytes", minimum=0)
        try:
            data = os.pread(self.fileno(), max_bytes, 0)
        except OSError:
            raise FilesystemReadError() from None
        self.recheck()
        return data


class OpenedDirectory(_OpenedObject):
    """A validated directory used as a stable descriptor-relative parent."""

    _kind: FileKind = "directory"

    def __init__(
        self,
        path: os.PathLike[str] | str,
        *,
        policy: DirectoryPolicy | None = None,
        expected_identity: ExpectedIdentity | None = None,
        dir_fd: OpenedDirectory | None = None,
    ) -> None:
        if policy is not None and not isinstance(policy, DirectoryPolicy):
            raise TypeError("directory policy must be a DirectoryPolicy")
        super().__init__(
            path,
            policy=policy or DirectoryPolicy(),
            expected_identity=expected_identity,
            dir_fd=dir_fd,
        )
        self.directory_identity = self.identity.directory

    def identity_at(self, name: os.PathLike[str] | str) -> FileIdentity | _Absent:
        return identity_at(name, dir_fd=self)

    def open_file(
        self,
        name: os.PathLike[str] | str,
        *,
        policy: FilePolicy | None = None,
        expected_identity: ExpectedIdentity | None = None,
    ) -> OpenedFile:
        return OpenedFile(
            _single_name(name),
            policy=policy,
            expected_identity=expected_identity,
            dir_fd=self,
        )

    def open_directory(
        self,
        name: os.PathLike[str] | str,
        *,
        policy: DirectoryPolicy | None = None,
        expected_identity: ExpectedIdentity | None = None,
    ) -> OpenedDirectory:
        return OpenedDirectory(
            _single_name(name),
            policy=policy,
            expected_identity=expected_identity,
            dir_fd=self,
        )


def open_descendant_file(
    root: OpenedDirectory,
    components: Sequence[str],
    *,
    directory_policy: DirectoryPolicy | None = None,
    file_policy: FilePolicy | None = None,
    expected_identity: ExpectedIdentity | None = None,
) -> OpenedFile:
    """Open a descendant while applying one policy to every child directory."""

    if not isinstance(root, OpenedDirectory):
        raise TypeError("root must be an OpenedDirectory")
    names = tuple(components)
    if not names:
        raise ValueError("components must contain a file name")
    if any(not isinstance(name, str) for name in names):
        raise TypeError("components must contain strings")

    current = root
    owned: OpenedDirectory | None = None
    try:
        for name in names[:-1]:
            child = current.open_directory(name, policy=directory_policy)
            if owned is not None:
                owned.close()
            owned = child
            current = child
        return current.open_file(
            names[-1],
            policy=file_policy,
            expected_identity=expected_identity,
        )
    finally:
        if owned is not None:
            owned.close()


def _metadata_kind(mode: int) -> str:
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISREG(mode):
        return "regular"
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISFIFO(mode):
        return "fifo"
    if stat.S_ISSOCK(mode):
        return "socket"
    if stat.S_ISCHR(mode):
        return "character-device"
    if stat.S_ISBLK(mode):
        return "block-device"
    return "unknown"


def _metadata(relative: tuple[str, ...], result: os.stat_result) -> MetadataEntry:
    return MetadataEntry(
        relative=relative,
        dev=result.st_dev,
        ino=result.st_ino,
        uid=result.st_uid,
        permissions=stat.S_IMODE(result.st_mode),
        links=result.st_nlink,
        size=result.st_size,
        mtime_ns=result.st_mtime_ns,
        ctime_ns=result.st_ctime_ns,
        kind=_metadata_kind(result.st_mode),
    )


def _stat_metadata(
    directory: OpenedDirectory,
    name: str,
    relative: tuple[str, ...],
) -> tuple[MetadataEntry, os.stat_result]:
    try:
        result = os.stat(name, dir_fd=directory.fileno(), follow_symlinks=False)
    except OSError:
        raise FilesystemTraversalError() from None
    return _metadata(relative, result), result


def _walk_metadata(
    directory: OpenedDirectory,
    relative: tuple[str, ...],
    root_device: int,
    xdev: bool,
) -> Iterator[MetadataEntry]:
    try:
        names = sorted(os.listdir(directory.fileno()), key=os.fsencode)
    except OSError:
        raise FilesystemTraversalError() from None

    for name in names:
        child_relative = (*relative, name)
        before, before_stat = _stat_metadata(directory, name, child_relative)
        yield before
        if before.kind == "directory" and (not xdev or before.dev == root_device):
            try:
                expected = identity_from_stat(before_stat)
                child = directory.open_directory(name, expected_identity=expected)
            except FilesystemError:
                raise FilesystemTraversalError() from None
            try:
                yield from _walk_metadata(child, child_relative, root_device, xdev)
                child.recheck()
            except FilesystemTraversalError:
                raise
            except FilesystemError:
                raise FilesystemTraversalError() from None
            finally:
                child.close()
        after, _after_stat = _stat_metadata(directory, name, child_relative)
        if after != before:
            raise FilesystemTraversalError()
    try:
        directory.recheck()
    except FilesystemError:
        raise FilesystemTraversalError() from None


def walk_metadata(
    root: OpenedDirectory,
    *,
    xdev: bool = True,
) -> Iterator[MetadataEntry]:
    """Enumerate a pinned tree without following links or reading file content."""

    if not isinstance(root, OpenedDirectory):
        raise TypeError("root must be an OpenedDirectory")
    if not isinstance(xdev, bool):
        raise TypeError("xdev must be a boolean")
    try:
        root_identity = root.recheck()
        yield _metadata((), os.fstat(root.fileno()))
        yield from _walk_metadata(root, (), root_identity.dev, xdev)
        root.recheck()
    except FilesystemTraversalError:
        raise
    except (OSError, FilesystemError):
        raise FilesystemTraversalError() from None


def read_bounded(opened_file: OpenedFile, max_bytes: int) -> bytes:
    if not isinstance(opened_file, OpenedFile):
        raise TypeError("opened_file must be an OpenedFile")
    return opened_file.read(max_bytes)


def fsync_file(opened_file: OpenedFile) -> None:
    if not isinstance(opened_file, OpenedFile):
        raise TypeError("opened_file must be an OpenedFile")
    failed = False
    try:
        os.fsync(opened_file.fileno())
    except OSError:
        failed = True
    if failed:
        raise FilesystemSyncError()


def fsync_directory(opened_directory: OpenedDirectory) -> None:
    if not isinstance(opened_directory, OpenedDirectory):
        raise TypeError("opened_directory must be an OpenedDirectory")
    failed = False
    try:
        os.fsync(opened_directory.fileno())
    except OSError:
        failed = True
    if failed:
        raise FilesystemSyncError()


def fsync_rename_parents(
    source_parent: OpenedDirectory,
    destination_parent: OpenedDirectory,
) -> None:
    """Synchronize source then destination, deduplicating the same directory."""

    if not isinstance(source_parent, OpenedDirectory) or not isinstance(
        destination_parent,
        OpenedDirectory,
    ):
        raise TypeError("rename parents must be OpenedDirectory objects")
    fsync_directory(source_parent)
    if (
        source_parent.directory_identity.dev,
        source_parent.directory_identity.ino,
    ) != (
        destination_parent.directory_identity.dev,
        destination_parent.directory_identity.ino,
    ):
        fsync_directory(destination_parent)


def _validate_trusted(identity: FileIdentity, current_uid: int) -> None:
    writable = identity.permissions & 0o022
    sticky = identity.permissions & stat.S_ISVTX
    if (
        identity.kind != "directory"
        or identity.uid not in (0, current_uid)
        or (writable and not sticky)
    ):
        raise TrustedAncestorError()


def open_trusted_directory(
    path: os.PathLike[str] | str,
    *,
    current_uid: int | None = None,
) -> OpenedDirectory:
    """Open an absolute directory after validating every component from ``/``."""

    value = _path_text(path)
    if not value.startswith("/"):
        raise ValueError("trusted traversal requires an absolute path")
    uid = os.geteuid() if current_uid is None else current_uid
    _policy_integer(uid, "current_uid", minimum=0)
    _base, components = _split_path(value)

    current = OpenedDirectory("/")
    try:
        _validate_trusted(current.identity, uid)
        for component in components:
            next_directory = current.open_directory(component)
            try:
                _validate_trusted(next_directory.identity, uid)
            except BaseException:
                next_directory.close()
                raise
            try:
                current.close()
            except BaseException:
                next_directory.close()
                raise
            current = next_directory
        return current
    except BaseException:
        current.close()
        raise


def validate_trusted_ancestors(
    path: os.PathLike[str] | str,
    *,
    current_uid: int | None = None,
) -> DirectoryIdentity:
    """Validate a fully existing absolute directory and close its descriptor."""

    directory = open_trusted_directory(path, current_uid=current_uid)
    try:
        return directory.directory_identity
    finally:
        directory.close()
