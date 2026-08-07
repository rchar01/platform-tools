"""Bounded, exact-argv subprocess execution for PKI operations."""

from __future__ import annotations

import math
import os
import selectors
import signal
import subprocess
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import TracebackType

from .errors import ApplicationError, shell_status


_READ_SIZE = 64 * 1024
_POLL_INTERVAL = 0.05


class ProcessSpawnError(ApplicationError):
    def __init__(self) -> None:
        super().__init__("External command could not be started")


class ProcessTimeoutError(ApplicationError):
    def __init__(self) -> None:
        super().__init__("External command timed out")


class ProcessOutputOverflowError(ApplicationError):
    def __init__(self) -> None:
        super().__init__("External command output exceeded its limit")


class ProcessExecutionError(ApplicationError):
    def __init__(self) -> None:
        super().__init__("External command execution failed")


@dataclass(frozen=True, slots=True, repr=False)
class ProcessResult:
    """A completed command result whose representation never reveals output."""

    status: int
    stdout: bytes
    stderr: bytes

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(status={self.status}, "
            "stdout=<redacted>, stderr=<redacted>)"
        )

    __str__ = __repr__


def _positive_number(value: object, name: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value <= 0
    ):
        raise ValueError(f"{name} must be a positive finite number")
    return float(value)


def _byte_limit(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} must be a nonnegative integer")
    return value


def _validate_argv(argv: object) -> tuple[str, ...]:
    if isinstance(argv, (str, bytes)) or not isinstance(argv, Sequence):
        raise TypeError("argv must be a sequence of strings")
    if not argv:
        raise ValueError("argv must not be empty")
    if any(not isinstance(argument, str) for argument in argv):
        raise TypeError("argv entries must be strings")
    if any("\0" in argument for argument in argv):
        raise ValueError("argv entries must not contain NUL bytes")
    return tuple(argv)


def _validate_environment(environment: object) -> dict[str, str]:
    if not isinstance(environment, Mapping):
        raise TypeError("env must be a mapping of strings to strings")
    if any(
        not isinstance(name, str) or not isinstance(value, str)
        for name, value in environment.items()
    ):
        raise TypeError("env must be a mapping of strings to strings")
    if any(
        not name or "=" in name or "\0" in name or "\0" in value
        for name, value in environment.items()
    ):
        raise ValueError("env contains an invalid name or value")
    return dict(environment)


def _validate_pass_fds(pass_fds: object) -> tuple[int, ...]:
    if isinstance(pass_fds, (str, bytes)) or not isinstance(pass_fds, Sequence):
        raise TypeError("pass_fds must be a sequence of integers")
    descriptors = tuple(pass_fds)
    if any(
        isinstance(descriptor, bool)
        or not isinstance(descriptor, int)
        or descriptor < 3
        for descriptor in descriptors
    ):
        raise ValueError("pass_fds must contain descriptors of at least 3")
    if len(descriptors) != len(set(descriptors)):
        raise ValueError("pass_fds must not contain duplicates")
    invalid = False
    for descriptor in descriptors:
        try:
            os.fstat(descriptor)
        except OSError:
            invalid = True
            break
    if invalid:
        raise ValueError("pass_fds must contain open descriptors")
    return tuple(sorted(descriptors))


def _close_stream(stream: object | None) -> None:
    if stream is None:
        return
    try:
        stream.close()  # type: ignore[union-attr]
    except OSError:
        pass


def _unregister_close(selector: selectors.BaseSelector, stream: object) -> None:
    try:
        selector.unregister(stream)  # type: ignore[arg-type]
    except (KeyError, OSError, ValueError):
        pass
    _close_stream(stream)


def _signal_group(process_group: int, process_signal: signal.Signals) -> bool:
    try:
        os.killpg(process_group, process_signal)
    except ProcessLookupError:
        return False
    except OSError:
        return False
    return True


def _group_exists(process_group: int) -> bool:
    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True
    return True


def _group_has_live_members(process_group: int) -> bool:
    """Ignore killed zombies while confirming that a process group is inert."""

    try:
        entries = os.scandir("/proc")
    except OSError:
        return _group_exists(process_group)
    with entries:
        for entry in entries:
            if not entry.name.isdigit():
                continue
            try:
                with open(f"{entry.path}/stat", "rb") as stat_file:
                    fields = stat_file.read().rsplit(b") ", 1)[1].split()
                state = fields[0]
                member_group = int(fields[2])
            except (IndexError, OSError, ValueError):
                continue
            if member_group == process_group and state != b"Z":
                return True
    return False


def _discard_ready(selector: selectors.BaseSelector | None, wait: float) -> None:
    if selector is None:
        time.sleep(max(0.0, wait))
        return
    try:
        events = selector.select(max(0.0, wait))
    except OSError:
        return
    for key, mask in events:
        stream = key.fileobj
        if key.data == "stdin":
            _unregister_close(selector, stream)
            continue
        if not mask & selectors.EVENT_READ:
            continue
        try:
            chunk = os.read(stream.fileno(), _READ_SIZE)  # type: ignore[union-attr]
        except (BlockingIOError, OSError, ValueError):
            chunk = b""
        if not chunk:
            _unregister_close(selector, stream)


def _terminate_and_reap(
    process: subprocess.Popen[bytes],
    selector: selectors.BaseSelector | None,
    grace: float,
) -> bool:
    """Best-effort bounded cleanup; never propagate raw subprocess failures."""

    _close_stream(process.stdin)
    process_group = process.pid
    _signal_group(process_group, signal.SIGTERM)
    deadline = time.monotonic() + grace
    while time.monotonic() < deadline:
        if process.poll() is not None and not _group_has_live_members(process_group):
            break
        _discard_ready(selector, min(_POLL_INTERVAL, deadline - time.monotonic()))

    if _group_has_live_members(process_group):
        _signal_group(process_group, signal.SIGKILL)
    if process.poll() is None:
        try:
            process.kill()
        except OSError:
            pass

    reap_deadline = time.monotonic() + grace
    while process.poll() is None and time.monotonic() < reap_deadline:
        _discard_ready(
            selector,
            min(_POLL_INTERVAL, reap_deadline - time.monotonic()),
        )
    try:
        process.wait(timeout=max(0.0, reap_deadline - time.monotonic()))
    except (OSError, subprocess.SubprocessError):
        return False
    return process.poll() is not None


def _remove_remaining_group(process_group: int, grace: float) -> bool:
    """Do not allow a successful command to leave background group members."""

    if not _signal_group(process_group, signal.SIGTERM):
        return True
    deadline = time.monotonic() + grace
    while _group_has_live_members(process_group) and time.monotonic() < deadline:
        time.sleep(min(0.01, deadline - time.monotonic()))
    if _group_has_live_members(process_group):
        _signal_group(process_group, signal.SIGKILL)
    deadline = time.monotonic() + grace
    while _group_has_live_members(process_group) and time.monotonic() < deadline:
        time.sleep(min(0.01, deadline - time.monotonic()))
    return not _group_has_live_members(process_group)


def run_process(
    argv: Sequence[str],
    *,
    env: Mapping[str, str],
    timeout: float,
    term_grace: float,
    stdout_limit: int,
    stderr_limit: int,
    input: bytes | None = None,
    pass_fds: Sequence[int] = (),
    cwd: str | None = None,
    return_result: bool = True,
) -> ProcessResult | None:
    """Run one exact argv with bounded byte capture and fail-closed cleanup."""

    arguments = _validate_argv(argv)
    environment = _validate_environment(env)
    effective_timeout = _positive_number(timeout, "timeout")
    effective_grace = _positive_number(term_grace, "term_grace")
    stdout_cap = _byte_limit(stdout_limit, "stdout_limit")
    stderr_cap = _byte_limit(stderr_limit, "stderr_limit")
    descriptors = _validate_pass_fds(pass_fds)
    if input is not None and not isinstance(input, bytes):
        raise TypeError("input must be bytes or None")
    if cwd is not None and not isinstance(cwd, str):
        raise TypeError("cwd must be a string or None")
    if cwd is not None and "\0" in cwd:
        raise ValueError("cwd must not contain NUL bytes")
    if not isinstance(return_result, bool):
        raise TypeError("return_result must be a boolean")

    process: subprocess.Popen[bytes] | None = None
    spawn_failed = False
    try:
        process = subprocess.Popen(
            arguments,
            cwd=cwd,
            env=environment,
            shell=False,
            start_new_session=True,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
            close_fds=True,
            pass_fds=descriptors,
        )
    except Exception:
        spawn_failed = True
    if spawn_failed:
        raise ProcessSpawnError()
    assert process is not None
    assert process.stdin is not None
    assert process.stdout is not None
    assert process.stderr is not None

    selector: selectors.BaseSelector | None = None
    stdout = bytearray()
    stderr = bytearray()
    captures = {
        "stdout": (stdout, stdout_cap),
        "stderr": (stderr, stderr_cap),
    }
    payload: memoryview | None = None
    overflow = False
    timed_out = False
    execution_failed = False
    interrupted: tuple[type[BaseException], BaseException, TracebackType | None] | None = None

    try:
        selector = selectors.DefaultSelector()
        payload = memoryview(input or b"")
        for stream, name in (
            (process.stdout, "stdout"),
            (process.stderr, "stderr"),
        ):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        if payload:
            os.set_blocking(process.stdin.fileno(), False)
            selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
        else:
            process.stdin.close()

        deadline = time.monotonic() + effective_timeout
        leader_cleanup_deadline: float | None = None
        while True:
            now = time.monotonic()
            if leader_cleanup_deadline is None and now >= deadline:
                timed_out = True
                break
            output_open = any(
                key.data in captures for key in selector.get_map().values()
            )
            if process.poll() is not None:
                if leader_cleanup_deadline is None:
                    if not _remove_remaining_group(process.pid, effective_grace):
                        execution_failed = True
                        break
                    leader_cleanup_deadline = time.monotonic() + effective_grace
                if not output_open:
                    break
                if time.monotonic() >= leader_cleanup_deadline:
                    execution_failed = True
                    break

            active_deadline = leader_cleanup_deadline or deadline
            wait = min(_POLL_INTERVAL, max(0.0, active_deadline - time.monotonic()))
            for key, mask in selector.select(wait):
                stream = key.fileobj
                if key.data == "stdin":
                    try:
                        written = os.write(stream.fileno(), payload)  # type: ignore[union-attr]
                    except BrokenPipeError:
                        written = len(payload)
                    payload = payload[written:]
                    if not payload:
                        _unregister_close(selector, stream)
                    continue
                if not mask & selectors.EVENT_READ:
                    continue
                try:
                    chunk = os.read(stream.fileno(), _READ_SIZE)  # type: ignore[union-attr]
                except BlockingIOError:
                    continue
                if not chunk:
                    _unregister_close(selector, stream)
                    continue
                destination, limit = captures[key.data]
                available = limit - len(destination)
                if len(chunk) > available:
                    if available:
                        destination.extend(chunk[:available])
                    overflow = True
                    break
                destination.extend(chunk)
            if overflow:
                break
    except (KeyboardInterrupt, SystemExit) as error:
        interrupted = (type(error), error, error.__traceback__)
    except Exception:
        execution_failed = True

    failed = overflow or timed_out or execution_failed or interrupted is not None
    cleanup_ok = True
    if failed:
        cleanup_ok = _terminate_and_reap(process, selector, effective_grace)
    else:
        try:
            process.wait(timeout=effective_grace)
        except (OSError, subprocess.SubprocessError):
            cleanup_ok = _terminate_and_reap(process, selector, effective_grace)
        else:
            cleanup_ok = _remove_remaining_group(process.pid, effective_grace)

    for stream in (process.stdin, process.stdout, process.stderr):
        if selector is None:
            _close_stream(stream)
        else:
            _unregister_close(selector, stream)
    if selector is not None:
        selector.close()
    if payload is not None:
        payload.release()

    if interrupted is not None:
        _, error, traceback = interrupted
        raise error.with_traceback(traceback)
    if overflow:
        raise ProcessOutputOverflowError()
    if timed_out:
        raise ProcessTimeoutError()
    if execution_failed or not cleanup_ok or process.returncode is None:
        raise ProcessExecutionError()

    result = ProcessResult(shell_status(process.returncode), bytes(stdout), bytes(stderr))
    return result if return_result else None
