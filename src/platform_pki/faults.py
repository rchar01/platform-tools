"""Deterministic fault and pause hooks for transaction tests."""

from __future__ import annotations

import math
import os
import secrets
import signal
import time
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .errors import ApplicationError
from .filesystem import (
    ABSENT,
    FilePolicy,
    FilesystemError,
    OpenedDirectory,
)


_DEFAULT_POLL_INTERVAL = 0.01


class InjectedFaultError(ApplicationError):
    """A deliberately injected, publicly safe operation failure."""

    def __init__(self) -> None:
        super().__init__("Injected operation failure")


class PauseHookError(ApplicationError):
    """A publicly safe pause-barrier failure."""

    def __init__(self) -> None:
        super().__init__("Pause hook failed")


def _has_control(value: str) -> bool:
    return any(
        unicodedata.category(character) in {"Cc", "Cf", "Cs", "Zl", "Zp"}
        for character in value
    )


def _optional_point(value: object, name: str) -> str | None:
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string or None")
    if _has_control(value):
        raise ValueError(f"{name} must not contain control characters")
    return value


def _point(value: object) -> str:
    if not isinstance(value, str):
        raise TypeError("fault point must be a string")
    if not value or _has_control(value):
        raise ValueError("fault point must be nonempty and contain no control characters")
    return value


def _path(value: object, name: str) -> str | None:
    if value is None:
        return None
    try:
        path = os.fspath(value)  # type: ignore[arg-type]
    except TypeError:
        raise TypeError(f"{name} must be a string path or None") from None
    if not isinstance(path, str):
        raise TypeError(f"{name} must be a string path or None")
    if not path or "\0" in path or _has_control(path):
        raise ValueError(f"{name} must be nonempty and contain no control characters")
    if os.path.basename(path) in {"", ".", ".."}:
        raise ValueError(f"{name} must name a filesystem entry")
    return path


@dataclass(frozen=True, slots=True)
class FaultHook:
    """Apply one literal-point fault in crash, signal, then failure order."""

    crash_at: str | None = None
    signal_at: str | None = None
    failure_at: str | None = None
    signum: int | signal.Signals = signal.SIGTERM

    def __post_init__(self) -> None:
        object.__setattr__(self, "crash_at", _optional_point(self.crash_at, "crash_at"))
        object.__setattr__(self, "signal_at", _optional_point(self.signal_at, "signal_at"))
        object.__setattr__(
            self,
            "failure_at",
            _optional_point(self.failure_at, "failure_at"),
        )
        if isinstance(self.signum, bool) or not isinstance(self.signum, int):
            raise TypeError("signum must be a valid process signal")
        try:
            process_signal = signal.Signals(self.signum)
        except ValueError:
            raise ValueError("signum must be a valid process signal") from None
        object.__setattr__(self, "signum", process_signal)

    def __call__(self, point: str) -> None:
        current = _point(point)
        if self.crash_at == current:
            os.kill(os.getpid(), signal.SIGKILL)
        if self.signal_at == current:
            os.kill(os.getpid(), self.signum)
        if self.failure_at == current:
            raise InjectedFaultError()


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    try:
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("pause marker write made no progress")
            view = view[written:]
    finally:
        view.release()


def _publish_marker(parent: OpenedDirectory, name: str, data: bytes) -> None:
    parent_descriptor = parent.fileno()
    marker_descriptor = -1
    temporary_name: str | None = None
    failed = False
    try:
        marker_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        marker_flags |= os.O_NOFOLLOW
        for _attempt in range(16):
            temporary_name = f".{name}.pause-{secrets.token_hex(16)}"
            try:
                marker_descriptor = os.open(
                    temporary_name,
                    marker_flags,
                    0o600,
                    dir_fd=parent_descriptor,
                )
            except FileExistsError:
                continue
            break
        else:
            raise OSError("could not reserve a pause marker staging file")

        _write_all(marker_descriptor, data)
        os.fsync(marker_descriptor)
        os.close(marker_descriptor)
        marker_descriptor = -1

        os.link(
            temporary_name,
            name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        os.unlink(temporary_name, dir_fd=parent_descriptor)
        temporary_name = None
        os.fsync(parent_descriptor)
    except OSError:
        failed = True
    finally:
        if marker_descriptor >= 0:
            try:
                os.close(marker_descriptor)
            except OSError:
                failed = True
        if temporary_name is not None:
            try:
                os.unlink(temporary_name, dir_fd=parent_descriptor)
            except OSError:
                failed = True
    if failed:
        raise PauseHookError()
    try:
        with parent.open_file(
            name,
            policy=FilePolicy(mode=0o600, links=1, max_size=len(data)),
        ) as marker:
            if marker.read(len(data)) != data:
                raise PauseHookError()
        parent.recheck()
    except FilesystemError:
        raise PauseHookError() from None


def _release_exists(parent: OpenedDirectory, name: str) -> bool:
    try:
        identity = parent.identity_at(name)
        parent.recheck()
    except FilesystemError:
        raise PauseHookError() from None
    return identity is not ABSENT


@dataclass(frozen=True, slots=True)
class PauseHook:
    """Publish a no-clobber marker, then wait indefinitely for a release path."""

    pause_at: str | None = None
    marker: str | os.PathLike[str] | None = None
    release: str | os.PathLike[str] | None = None
    marker_bytes: bytes = b""
    poll_interval: float = _DEFAULT_POLL_INTERVAL
    marker_callback: Callable[[Path], None] | None = None

    def __post_init__(self) -> None:
        pause_at = _optional_point(self.pause_at, "pause_at")
        marker = _path(self.marker, "marker")
        release = _path(self.release, "release")
        object.__setattr__(self, "pause_at", pause_at)
        object.__setattr__(self, "marker", marker)
        object.__setattr__(self, "release", release)

        if pause_at is not None and (marker is None or release is None):
            raise ValueError("an enabled pause hook requires marker and release paths")
        if (marker is None) != (release is None):
            raise ValueError("marker and release paths must be configured together")
        if marker is not None and release is not None:
            if os.path.abspath(marker) == os.path.abspath(release):
                raise ValueError("marker and release paths must differ")
        if not isinstance(self.marker_bytes, bytes):
            raise TypeError("marker_bytes must be bytes")
        if (
            isinstance(self.poll_interval, bool)
            or not isinstance(self.poll_interval, (int, float))
            or not math.isfinite(self.poll_interval)
            or self.poll_interval <= 0
        ):
            raise ValueError("poll_interval must be a positive finite number")
        object.__setattr__(self, "poll_interval", float(self.poll_interval))
        if self.marker_callback is not None and not callable(self.marker_callback):
            raise TypeError("marker_callback must be callable or None")

    def __call__(self, point: str) -> None:
        current = _point(point)
        if self.pause_at != current:
            return
        assert isinstance(self.marker, str)
        assert isinstance(self.release, str)
        marker_parent_path = os.path.dirname(self.marker) or "."
        marker_name = os.path.basename(self.marker)
        release_parent_path = os.path.dirname(self.release) or "."
        release_name = os.path.basename(self.release)

        try:
            with OpenedDirectory(marker_parent_path) as marker_parent:
                with OpenedDirectory(release_parent_path) as release_parent:
                    _release_exists(release_parent, release_name)
                    _publish_marker(marker_parent, marker_name, self.marker_bytes)

                    callback_failed = False
                    if self.marker_callback is not None:
                        try:
                            self.marker_callback(Path(self.marker))
                        except Exception:
                            callback_failed = True
                    if callback_failed:
                        raise PauseHookError()

                    while not _release_exists(release_parent, release_name):
                        time.sleep(self.poll_interval)
        except FilesystemError:
            raise PauseHookError() from None


DEFAULT_FAULT_HOOK = FaultHook()
DEFAULT_PAUSE_HOOK = PauseHook()
