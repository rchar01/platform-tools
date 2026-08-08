"""Ordered, descriptor-bound advisory locks for PKI operations."""

from __future__ import annotations

import errno
import fcntl
import os
import threading
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import NoReturn

from .errors import ApplicationError
from .faults import DEFAULT_FAULT_HOOK, DEFAULT_PAUSE_HOOK
from .filesystem import (
    ABSENT,
    DirectoryPolicy,
    FileIdentity,
    FilePolicy,
    FilesystemError,
    OpenedDirectory,
    identity_from_stat,
)
from .paths import validate_absolute_path


LOCK_ORDER = ("lifecycle", "root", "intermediate", "inventory", "export")
LOCK_PROFILES = tuple(LOCK_ORDER[:length] for length in range(1, len(LOCK_ORDER) + 1))
_CHECKPOINT_PHASES = (
    "after-pre-stat",
    "after-stage-init",
    "after-open",
    "after-acquire",
    "before-release",
    "after-release",
)
LOCK_CHECKPOINTS = tuple(
    f"lock-{name}-{phase}" for name in LOCK_ORDER for phase in _CHECKPOINT_PHASES
)
_PROFILE_BY_NAME: dict[str, tuple[str, ...]] = dict(
    zip(LOCK_ORDER, LOCK_PROFILES, strict=True)
)
_LOCK_FILE_FLAGS = os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC
_ANONYMOUS_LOCK_FILE_FLAGS = _LOCK_FILE_FLAGS | os.O_TMPFILE

Hook = Callable[[str], None]


class LockError(ApplicationError):
    """A lock failure safe to render without disclosing paths or hook points."""


class LockDuplicateError(LockError):
    def __init__(self) -> None:
        super().__init__("PKI lock is already held by this process")


class LockOrderError(LockError):
    def __init__(self) -> None:
        super().__init__("PKI lock profile is not an ordered prefix")


class LockPolicyError(LockError):
    def __init__(self) -> None:
        super().__init__("PKI lock state does not satisfy its policy")


class LockContentionError(LockError):
    def __init__(self, name: str | None = None) -> None:
        self.name = name
        super().__init__("Another PKI operation is in progress")


class LockAcquireError(LockError):
    def __init__(self) -> None:
        super().__init__("PKI lock could not be acquired")


class LockReleaseError(LockError):
    def __init__(self) -> None:
        super().__init__("PKI lock could not be released")


@dataclass(eq=False, slots=True)
class _ContextState:
    owner_pid: int
    keys: tuple[tuple[str, str], ...]
    descriptors: set[int] = field(default_factory=set)
    directories: list[OpenedDirectory] = field(default_factory=list)
    inherited: bool = False


_HELD_LOCKS: set[tuple[str, str]] = set()
_ACTIVE_CONTEXTS: set[_ContextState] = set()
_REGISTRY_GUARD = threading.Lock()
_REGISTRY_PID = os.getpid()


def _discard_inherited_directory(directory: OpenedDirectory, descriptors: set[int]) -> None:
    descriptor = directory._fd
    if descriptor >= 0:
        descriptors.add(descriptor)
    for binding in directory._bindings:
        descriptors.add(binding.parent_fd)
    directory._fd = -1
    directory._bindings = ()


def _at_fork_before() -> None:
    _REGISTRY_GUARD.acquire()


def _at_fork_parent() -> None:
    _REGISTRY_GUARD.release()


def _at_fork_child() -> None:
    global _REGISTRY_PID

    descriptors: set[int] = set()
    for state in _ACTIVE_CONTEXTS:
        state.inherited = True
        descriptors.update(state.descriptors)
        for directory in state.directories:
            _discard_inherited_directory(directory, descriptors)
        state.descriptors.clear()
        state.directories.clear()
    for descriptor in descriptors:
        try:
            os.close(descriptor)
        except OSError:
            pass
    _ACTIVE_CONTEXTS.clear()
    _HELD_LOCKS.clear()
    _REGISTRY_PID = os.getpid()
    _REGISTRY_GUARD.release()


try:
    os.register_at_fork(
        before=_at_fork_before,
        after_in_parent=_at_fork_parent,
        after_in_child=_at_fork_child,
    )
except AttributeError as error:  # pragma: no cover - supported runtime is Linux
    raise RuntimeError("platform-pki requires os.register_at_fork") from error


def _pki_path(value: object) -> str:
    try:
        path = os.fspath(value)  # type: ignore[arg-type]
    except TypeError:
        raise TypeError("pki_dir must be text or a text path-like object") from None
    if not isinstance(path, str):
        raise TypeError("pki_dir must be text or a text path-like object")
    return validate_absolute_path(path)


def _profile_names(profile: object) -> tuple[str, ...]:
    if isinstance(profile, str):
        names = _PROFILE_BY_NAME.get(profile)
        if names is None:
            raise LockOrderError()
        return names
    if not isinstance(profile, Sequence):
        raise LockOrderError()
    names = tuple(profile)
    if (
        not names
        or not all(isinstance(name, str) for name in names)
        or names not in LOCK_PROFILES
    ):
        raise LockOrderError()
    return names  # type: ignore[return-value]


def _reserve_context(path: str, names: tuple[str, ...]) -> _ContextState:
    global _REGISTRY_PID

    keys = tuple((path, name) for name in names)
    with _REGISTRY_GUARD:
        pid = os.getpid()
        if pid != _REGISTRY_PID:
            _HELD_LOCKS.clear()
            _ACTIVE_CONTEXTS.clear()
            _REGISTRY_PID = pid
        if any(key in _HELD_LOCKS for key in keys):
            raise LockDuplicateError()
        state = _ContextState(pid, keys)
        _HELD_LOCKS.update(keys)
        _ACTIVE_CONTEXTS.add(state)
        return state


def _unregister_context(state: _ContextState) -> None:
    with _REGISTRY_GUARD:
        _ACTIVE_CONTEXTS.discard(state)
        _HELD_LOCKS.difference_update(state.keys)


def _checkpoint(name: str, phase: str, fault_hook: Hook, pause_hook: Hook) -> None:
    point = f"lock-{name}-{phase}"
    fault_hook(point)
    pause_hook(point)


def _lock_signature(identity: FileIdentity) -> tuple[int, int, int, int, int, str]:
    return (
        identity.dev,
        identity.ino,
        identity.uid,
        identity.permissions,
        identity.links,
        identity.kind,
    )


def _validate_lock_file(identity: FileIdentity, uid: int) -> None:
    try:
        FilePolicy(owner=uid, mode=0o600, links=1).validate(identity)
    except FilesystemError:
        raise LockPolicyError() from None


def _identity_at(
    lock_directory: OpenedDirectory,
    name: str,
    *,
    acquiring: bool = False,
):
    try:
        with _REGISTRY_GUARD:
            return lock_directory.identity_at(name)
    except FilesystemError:
        if acquiring:
            raise LockAcquireError() from None
        raise LockPolicyError() from None


def _fstat_lock(descriptor: int) -> FileIdentity:
    try:
        return identity_from_stat(os.fstat(descriptor))
    except (OSError, FilesystemError):
        raise LockAcquireError() from None


def _track_directory(state: _ContextState, directory: OpenedDirectory) -> None:
    state.directories.append(directory)


def _open_tracked(
    state: _ContextState,
    name: str,
    flags: int,
    parent_descriptor: int,
) -> int:
    with _REGISTRY_GUARD:
        try:
            descriptor = os.open(name, flags, 0o600, dir_fd=parent_descriptor)
        except OSError:
            raise LockAcquireError() from None
        state.descriptors.add(descriptor)
    return descriptor


def _close_tracked(
    state: _ContextState,
    descriptor: int,
    *,
    unlock: bool,
) -> BaseException | None:
    failure: BaseException | None = None
    with _REGISTRY_GUARD:
        if unlock:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            except OSError:
                failure = LockReleaseError()
        try:
            os.close(descriptor)
        except OSError:
            failure = failure or LockReleaseError()
        state.descriptors.discard(descriptor)
    return failure


def _raise_primary(
    primary: BaseException,
    cleanup: BaseException | None,
) -> NoReturn:
    if cleanup is not None:
        raise primary from cleanup
    raise primary


def _create_anonymous_lock(
    state: _ContextState,
    lock_directory: OpenedDirectory,
    uid: int,
) -> tuple[int, FileIdentity]:
    descriptor = _open_tracked(
        state,
        ".",
        _ANONYMOUS_LOCK_FILE_FLAGS,
        lock_directory.fileno(),
    )
    try:
        os.fchmod(descriptor, 0o600)
        if os.get_inheritable(descriptor):
            raise OSError(errno.EIO, "lock descriptor is inheritable")
        opened = _fstat_lock(descriptor)
        FilePolicy(owner=uid, mode=0o600).validate(opened)
        if opened.links != 0:
            raise LockAcquireError()
    except (OSError, LockError):
        close_failure = _close_tracked(state, descriptor, unlock=False)
        _raise_primary(LockAcquireError(), close_failure)
    return descriptor, opened


def _publish_anonymous_lock(
    lock_directory: OpenedDirectory,
    descriptor: int,
    name: str,
) -> None:
    try:
        with _REGISTRY_GUARD:
            os.link(
                f"/proc/self/fd/{descriptor}",
                name,
                dst_dir_fd=lock_directory.fileno(),
                follow_symlinks=True,
            )
    except OSError:
        raise LockAcquireError() from None


def _open_lock(
    state: _ContextState,
    lock_directory: OpenedDirectory,
    name: str,
    *,
    uid: int,
    no_state: bool,
    fault_hook: Hook,
    pause_hook: Hook,
) -> int:
    before = _identity_at(lock_directory, name)
    if before is not ABSENT:
        assert isinstance(before, FileIdentity)
        _validate_lock_file(before, uid)
    _checkpoint(name, "after-pre-stat", fault_hook, pause_hook)

    descriptor = -1
    locked = False
    try:
        if before is ABSENT:
            if no_state:
                raise LockPolicyError()
            descriptor, _anonymous = _create_anonymous_lock(
                state,
                lock_directory,
                uid,
            )
            _checkpoint(name, "after-stage-init", fault_hook, pause_hook)
            _publish_anonymous_lock(lock_directory, descriptor, name)
        else:
            descriptor = _open_tracked(
                state,
                name,
                _LOCK_FILE_FLAGS,
                lock_directory.fileno(),
            )
            if os.get_inheritable(descriptor):
                raise LockAcquireError()

        _checkpoint(name, "after-open", fault_hook, pause_hook)
        opened = _fstat_lock(descriptor)
        try:
            _validate_lock_file(opened, uid)
        except LockPolicyError:
            raise LockAcquireError() from None
        after = _identity_at(lock_directory, name, acquiring=True)
        if after is ABSENT:
            raise LockAcquireError()
        assert isinstance(after, FileIdentity)
        try:
            _validate_lock_file(after, uid)
        except LockPolicyError:
            raise LockAcquireError() from None
        signatures = {_lock_signature(opened), _lock_signature(after)}
        if before is not ABSENT:
            assert isinstance(before, FileIdentity)
            signatures.add(_lock_signature(before))
        if len(signatures) != 1:
            raise LockAcquireError()
        try:
            lock_directory.recheck()
        except FilesystemError:
            raise LockAcquireError() from None

        try:
            with _REGISTRY_GUARD:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            locked = True
        except OSError as error:
            if error.errno in (errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK):
                raise LockContentionError(name) from None
            raise LockAcquireError() from None

        _checkpoint(name, "after-acquire", fault_hook, pause_hook)
        final = _identity_at(lock_directory, name, acquiring=True)
        if final is ABSENT:
            raise LockAcquireError()
        assert isinstance(final, FileIdentity)
        try:
            _validate_lock_file(final, uid)
        except LockPolicyError:
            raise LockAcquireError() from None
        if _lock_signature(final) != _lock_signature(opened):
            raise LockAcquireError()
        try:
            lock_directory.recheck()
        except FilesystemError:
            raise LockAcquireError() from None
        return descriptor
    except BaseException as primary:
        cleanup: BaseException | None = None
        if descriptor >= 0:
            cleanup = _close_tracked(state, descriptor, unlock=locked)
        _raise_primary(primary, cleanup)


def _release_lock(
    state: _ContextState,
    name: str,
    descriptor: int,
    fault_hook: Hook,
    pause_hook: Hook,
) -> BaseException | None:
    failure: BaseException | None = None
    try:
        _checkpoint(name, "before-release", fault_hook, pause_hook)
    except BaseException as error:
        failure = error
    current = _close_tracked(state, descriptor, unlock=True)
    failure = failure or current
    try:
        _checkpoint(name, "after-release", fault_hook, pause_hook)
    except BaseException as error:
        failure = failure or error
    return failure


def _release_all(
    state: _ContextState,
    held: list[tuple[str, int]],
    fault_hook: Hook,
    pause_hook: Hook,
) -> BaseException | None:
    failure: BaseException | None = None
    for name, descriptor in reversed(held):
        current = _release_lock(state, name, descriptor, fault_hook, pause_hook)
        failure = failure or current
    held.clear()
    return failure


def _close_directories(state: _ContextState) -> BaseException | None:
    failure: BaseException | None = None
    with _REGISTRY_GUARD:
        for directory in reversed(state.directories):
            try:
                directory.close()
            except FilesystemError:
                failure = failure or LockReleaseError()
        state.directories.clear()
    return failure


@contextmanager
def acquire_pki_locks(
    pki_dir: str | os.PathLike[str],
    profile: str | Sequence[str],
    *,
    no_state: bool = False,
    fault_hook: Hook = DEFAULT_FAULT_HOOK,
    pause_hook: Hook = DEFAULT_PAUSE_HOOK,
) -> Iterator[None]:
    """Acquire one ordered lock prefix and release it in reverse order.

    A string profile names its final lock (for example, ``"inventory"``).
    Sequence profiles must equal one of ``LOCK_PROFILES``. In ``no_state`` mode
    every persistent lock file must already exist.
    """

    path = _pki_path(pki_dir)
    names = _profile_names(profile)
    if not isinstance(no_state, bool):
        raise TypeError("no_state must be a boolean")
    if not callable(fault_hook) or not callable(pause_hook):
        raise TypeError("lock hooks must be callable")

    state = _reserve_context(path, names)
    held: list[tuple[str, int]] = []
    primary: BaseException | None = None
    try:
        try:
            with _REGISTRY_GUARD:
                pki_directory = OpenedDirectory(path)
                _track_directory(state, pki_directory)
                lock_directory = pki_directory.open_directory(
                    "locks",
                    policy=DirectoryPolicy(owner=os.geteuid(), mode=0o700),
                )
                _track_directory(state, lock_directory)
                pki_directory.recheck()
        except FilesystemError:
            raise LockPolicyError() from None

        for name in names:
            descriptor = _open_lock(
                state,
                lock_directory,
                name,
                uid=os.geteuid(),
                no_state=no_state,
                fault_hook=fault_hook,
                pause_hook=pause_hook,
            )
            held.append((name, descriptor))
        yield None
    except BaseException as error:
        primary = error

    if state.owner_pid != os.getpid() or state.inherited:
        if primary is not None:
            raise primary
        return

    release_failure = _release_all(state, held, fault_hook, pause_hook)
    directory_failure = _close_directories(state)
    cleanup = release_failure or directory_failure
    _unregister_context(state)
    if primary is not None:
        _raise_primary(primary, cleanup)
    if cleanup is not None:
        raise cleanup
