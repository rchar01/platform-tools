from __future__ import annotations

import fcntl
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from src.platform_pki import locks
from src.platform_pki.errors import ApplicationError, shell_status
from src.platform_pki.faults import FaultHook
from src.platform_pki.filesystem import FileIdentity, identity_at
from src.platform_pki.locks import (
    LOCK_CHECKPOINTS,
    LOCK_ORDER,
    LOCK_PROFILES,
    LockAcquireError,
    LockContentionError,
    LockDuplicateError,
    LockError,
    LockOrderError,
    LockPolicyError,
    LockReleaseError,
    acquire_pki_locks,
)


ROOT = Path(__file__).resolve().parents[1]
PYTHON = sys.executable


def _pki(tmp_path: Path) -> Path:
    pki = tmp_path / "pki"
    pki.mkdir(mode=0o700)
    locks_dir = pki / "locks"
    locks_dir.mkdir(mode=0o700)
    locks_dir.chmod(0o700)
    return pki


def _lock_file(pki: Path, name: str) -> Path:
    path = pki / "locks" / name
    path.write_bytes(b"")
    path.chmod(0o600)
    return path


def _all_lock_files(pki: Path) -> None:
    for name in LOCK_ORDER:
        _lock_file(pki, name)


def _run_flock(path: Path) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ("flock", "-n", os.fspath(path), "true"),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=3,
        check=False,
    )


def _wait_for_path(path: Path, process: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        if path.exists():
            return
        if process.poll() is not None:
            pytest.fail(f"lock holder exited early with {process.returncode}")
        time.sleep(0.005)
    pytest.fail("timed out waiting for lock holder")


def _util_linux_holder(lock_path: Path, marker: Path) -> subprocess.Popen[bytes]:
    source = (
        "from pathlib import Path; import signal,sys; "
        "Path(sys.argv[1]).write_bytes(b'held'); signal.pause()"
    )
    process = subprocess.Popen(
        ("flock", "-n", os.fspath(lock_path), PYTHON, "-c", source, marker),
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    _wait_for_path(marker, process)
    return process


def _stop(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    process.communicate(timeout=3)


def test_all_profiles_acquire_in_order_and_release_lifo(tmp_path: Path) -> None:
    pki = _pki(tmp_path)
    assert LOCK_PROFILES == tuple(
        LOCK_ORDER[:length] for length in range(1, len(LOCK_ORDER) + 1)
    )
    assert len(LOCK_CHECKPOINTS) == len(LOCK_ORDER) * 6

    for final_name, profile in zip(LOCK_ORDER, LOCK_PROFILES, strict=True):
        events: list[str] = []
        with acquire_pki_locks(pki, final_name, fault_hook=events.append):
            acquired = [
                point.removeprefix("lock-").removesuffix("-after-acquire")
                for point in events
                if point.endswith("-after-acquire")
            ]
            assert acquired == list(profile)
            for name in profile:
                assert _run_flock(pki / "locks" / name).returncode == 1

        released = [
            point.removeprefix("lock-").removesuffix("-before-release")
            for point in events
            if point.endswith("-before-release")
        ]
        assert released == list(reversed(profile))
        for name in profile:
            assert _run_flock(pki / "locks" / name).returncode == 0


def test_exact_sequence_profiles_are_accepted_and_other_orders_rejected(
    tmp_path: Path,
) -> None:
    pki = _pki(tmp_path)
    with acquire_pki_locks(pki, LOCK_ORDER[:3]):
        pass

    invalid = (
        (),
        ("lifecycle", "intermediate"),
        ("root",),
        ("lifecycle", "root", "root"),
        (*LOCK_ORDER, "extra"),
        "unknown",
        3,
    )
    for profile in invalid:
        with pytest.raises(LockOrderError):
            with acquire_pki_locks(pki, profile):  # type: ignore[arg-type]
                pass


def test_normal_mode_creates_persistent_exact_mode_files_without_umask_drift(
    tmp_path: Path,
) -> None:
    pki = _pki(tmp_path)
    previous_umask = os.umask(0o777)
    try:
        with acquire_pki_locks(pki, "export"):
            pass
    finally:
        os.umask(previous_umask)

    assert tuple(path.name for path in sorted((pki / "locks").iterdir())) == tuple(
        sorted(LOCK_ORDER)
    )
    for name in LOCK_ORDER:
        path = pki / "locks" / name
        identity = path.stat()
        assert identity.st_mode & 0o777 == 0o600
        assert identity.st_uid == os.geteuid()
        assert identity.st_nlink == 1


def test_no_state_requires_every_file_and_creates_nothing(tmp_path: Path) -> None:
    pki = _pki(tmp_path)
    lifecycle = _lock_file(pki, "lifecycle")
    with pytest.raises(LockPolicyError):
        with acquire_pki_locks(pki, "root", no_state=True):
            pass
    assert lifecycle.exists()
    assert not (pki / "locks" / "root").exists()
    assert _run_flock(lifecycle).returncode == 0

    _lock_file(pki, "root")
    with acquire_pki_locks(pki, "root", no_state=True):
        pass


def test_arbitrary_lock_content_is_accepted_and_never_modified(tmp_path: Path) -> None:
    pki = _pki(tmp_path)
    lifecycle = _lock_file(pki, "lifecycle")
    payload = b"arbitrary\x00persistent\ncontent"
    lifecycle.write_bytes(payload)
    with acquire_pki_locks(pki, "lifecycle", no_state=True):
        assert lifecycle.read_bytes() == payload
    assert lifecycle.read_bytes() == payload
    assert lifecycle.exists()


@pytest.mark.parametrize("kind", ("symlink", "hardlink", "directory", "fifo", "mode"))
def test_lock_file_policy_rejects_links_types_and_wrong_mode(
    kind: str,
    tmp_path: Path,
) -> None:
    pki = _pki(tmp_path)
    path = pki / "locks" / "lifecycle"
    target = tmp_path / "target"
    target.write_bytes(b"")
    target.chmod(0o600)
    if kind == "symlink":
        path.symlink_to(target)
    elif kind == "hardlink":
        os.link(target, path)
    elif kind == "directory":
        path.mkdir(mode=0o700)
    elif kind == "fifo":
        os.mkfifo(path, mode=0o600)
    else:
        path.write_bytes(b"")
        path.chmod(0o640)

    with pytest.raises(LockPolicyError):
        with acquire_pki_locks(pki, "lifecycle", no_state=True):
            pass


def test_wrong_lock_owner_is_rejected(tmp_path: Path) -> None:
    pki = _pki(tmp_path)
    path = _lock_file(pki, "lifecycle")
    identity = identity_at(path)
    assert isinstance(identity, FileIdentity)
    with pytest.raises(LockPolicyError):
        locks._validate_lock_file(identity, os.geteuid() + 1)

    if os.geteuid() == 0:
        os.chown(path, 65534, -1)
        with pytest.raises(LockPolicyError):
            with acquire_pki_locks(pki, "lifecycle", no_state=True):
                pass


@pytest.mark.parametrize("phase", ("after-pre-stat", "after-open", "after-acquire"))
def test_lock_replacement_races_fail_closed_and_release_opened_inode(
    phase: str,
    tmp_path: Path,
) -> None:
    pki = _pki(tmp_path)
    path = _lock_file(pki, "lifecycle")
    path.write_bytes(b"original")
    replacement = tmp_path / "replacement"
    replacement.write_bytes(b"replacement")
    replacement.chmod(0o600)
    point = f"lock-lifecycle-{phase}"

    def replace(current: str) -> None:
        if current == point:
            os.replace(replacement, path)

    with pytest.raises(LockAcquireError):
        with acquire_pki_locks(pki, "lifecycle", no_state=True, pause_hook=replace):
            pass
    assert path.read_bytes() == b"replacement"
    assert _run_flock(path).returncode == 0


def test_missing_file_creation_race_does_not_open_competing_state(tmp_path: Path) -> None:
    pki = _pki(tmp_path)
    path = pki / "locks" / "lifecycle"

    def create(current: str) -> None:
        if current == "lock-lifecycle-after-stage-init":
            path.write_bytes(b"competing")
            path.chmod(0o600)

    with pytest.raises(LockAcquireError):
        with acquire_pki_locks(pki, "lifecycle", pause_hook=create):
            pass
    assert path.read_bytes() == b"competing"


def test_anonymous_creation_has_no_replaceable_staging_path(
    tmp_path: Path,
) -> None:
    pki = _pki(tmp_path)
    canonical = pki / "locks" / "lifecycle"

    def inspect_stage(point: str) -> None:
        if point != "lock-lifecycle-after-stage-init":
            return
        assert not tuple((pki / "locks").iterdir())
        raise RuntimeError("stop before publication")

    with pytest.raises(RuntimeError, match="stop before publication"):
        with acquire_pki_locks(pki, "lifecycle", pause_hook=inspect_stage):
            pass
    assert not canonical.exists()
    assert not tuple((pki / "locks").iterdir())


@pytest.mark.parametrize("phase", ("after-pre-stat", "after-open", "after-acquire"))
def test_full_directory_binding_detects_canonical_locks_replacement(
    phase: str,
    tmp_path: Path,
) -> None:
    pki = _pki(tmp_path)
    _lock_file(pki, "lifecycle")
    moved = pki / "moved-locks"
    point = f"lock-lifecycle-{phase}"

    def replace_directory(current: str) -> None:
        if current != point:
            return
        (pki / "locks").rename(moved)
        (pki / "locks").mkdir(mode=0o700)
        (pki / "locks").chmod(0o700)
        _lock_file(pki, "lifecycle")

    with pytest.raises(LockAcquireError):
        with acquire_pki_locks(
            pki,
            "lifecycle",
            no_state=True,
            pause_hook=replace_directory,
        ):
            pass
    assert _run_flock(pki / "locks" / "lifecycle").returncode == 0


def test_staged_creation_failure_cleans_private_file_and_publishes_nothing(
    tmp_path: Path,
) -> None:
    pki = _pki(tmp_path)
    point = "lock-lifecycle-after-stage-init"
    with pytest.raises(ApplicationError):
        with acquire_pki_locks(pki, "lifecycle", fault_hook=FaultHook(failure_at=point)):
            pass
    assert not tuple((pki / "locks").iterdir())


def test_sigkill_after_stage_initialization_never_publishes_wrong_mode_lock(
    tmp_path: Path,
) -> None:
    pki = _pki(tmp_path)
    source = (
        "import os,sys; from src.platform_pki.faults import FaultHook; "
        "from src.platform_pki.locks import acquire_pki_locks; os.umask(0o777); "
        "\nwith acquire_pki_locks(sys.argv[1], 'lifecycle', "
        "fault_hook=FaultHook(crash_at='lock-lifecycle-after-stage-init')): pass"
    )
    result = subprocess.run(
        (PYTHON, "-c", source, pki),
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=3,
        check=False,
    )
    assert shell_status(result.returncode) == 137
    assert result.stdout == result.stderr == b""
    assert not (pki / "locks" / "lifecycle").exists()
    assert not tuple((pki / "locks").iterdir())

    with acquire_pki_locks(pki, "lifecycle"):
        canonical = pki / "locks" / "lifecycle"
        assert canonical.stat().st_mode & 0o777 == 0o600


def test_python_process_contends_with_python_process(tmp_path: Path) -> None:
    pki = _pki(tmp_path)
    _lock_file(pki, "lifecycle")
    source = (
        "from src.platform_pki.locks import acquire_pki_locks,LockContentionError; "
        "import sys; "
        "\ntry:\n with acquire_pki_locks(sys.argv[1], 'lifecycle', no_state=True): pass"
        "\nexcept LockContentionError: print('contended')"
        "\nelse: raise SystemExit('unexpected acquisition')"
    )
    with acquire_pki_locks(pki, "lifecycle", no_state=True):
        result = subprocess.run(
            (PYTHON, "-c", source, pki),
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=3,
            check=False,
        )
    assert result.returncode == 0
    assert result.stdout == b"contended\n"
    assert result.stderr == b""


def test_python_lock_contends_with_util_linux_flock(tmp_path: Path) -> None:
    pki = _pki(tmp_path)
    path = _lock_file(pki, "lifecycle")
    with acquire_pki_locks(pki, "lifecycle", no_state=True):
        assert _run_flock(path).returncode == 1

    holder = _util_linux_holder(path, tmp_path / "bash-held")
    try:
        with pytest.raises(LockContentionError):
            with acquire_pki_locks(pki, "lifecycle", no_state=True):
                pass
    finally:
        _stop(holder)
    assert _run_flock(path).returncode == 0


def test_partial_acquisition_failure_releases_prior_locks(tmp_path: Path) -> None:
    pki = _pki(tmp_path)
    lifecycle = _lock_file(pki, "lifecycle")
    root = _lock_file(pki, "root")
    holder = _util_linux_holder(root, tmp_path / "root-held")
    try:
        with pytest.raises(LockContentionError):
            with acquire_pki_locks(pki, "root", no_state=True):
                pass
        assert _run_flock(lifecycle).returncode == 0
    finally:
        _stop(holder)


def test_body_exception_releases_every_lock(tmp_path: Path) -> None:
    pki = _pki(tmp_path)
    _all_lock_files(pki)
    body_error = RuntimeError("body failed")
    with pytest.raises(RuntimeError) as caught:
        with acquire_pki_locks(pki, "export", no_state=True):
            raise body_error
    assert caught.value is body_error
    for name in LOCK_ORDER:
        assert _run_flock(pki / "locks" / name).returncode == 0


def test_duplicate_process_local_acquisition_is_rejected(tmp_path: Path) -> None:
    pki = _pki(tmp_path)
    _lock_file(pki, "lifecycle")
    with acquire_pki_locks(pki, "lifecycle", no_state=True):
        with pytest.raises(LockDuplicateError):
            with acquire_pki_locks(pki, "lifecycle", no_state=True):
                pass


def test_duplicate_registry_is_thread_safe(tmp_path: Path) -> None:
    pki = _pki(tmp_path)
    _lock_file(pki, "lifecycle")
    entered = threading.Event()
    release = threading.Event()
    failures: list[BaseException] = []

    def holder() -> None:
        try:
            with acquire_pki_locks(pki, "lifecycle", no_state=True):
                entered.set()
                assert release.wait(3)
        except BaseException as error:
            failures.append(error)

    thread = threading.Thread(target=holder)
    thread.start()
    assert entered.wait(3)
    try:
        with pytest.raises(LockDuplicateError):
            with acquire_pki_locks(pki, "lifecycle", no_state=True):
                pass
    finally:
        release.set()
        thread.join(timeout=3)
    assert not thread.is_alive()
    assert failures == []


def _pki_descriptors(pki: Path) -> set[int]:
    descriptors: set[int] = set()
    for entry in Path("/proc/self/fd").iterdir():
        try:
            target = os.readlink(entry)
        except FileNotFoundError:
            continue
        if target.startswith(os.fspath(pki)):
            descriptors.add(int(entry.name))
    return descriptors


def test_fork_child_exits_inherited_context_without_unlock_or_fd_reuse_damage(
    tmp_path: Path,
) -> None:
    pki = _pki(tmp_path)
    path = _lock_file(pki, "lifecycle")
    events: list[str] = []
    manager = acquire_pki_locks(
        pki,
        "lifecycle",
        no_state=True,
        pause_hook=events.append,
    )
    manager.__enter__()
    inherited_descriptors = _pki_descriptors(pki)
    assert inherited_descriptors
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        opened: list[int] = []
        try:
            try:
                with acquire_pki_locks(pki, "lifecycle", no_state=True):
                    pass
            except LockContentionError:
                registry = b"contention"
            except LockDuplicateError:
                registry = b"duplicate"
            else:
                registry = b"acquired"

            remaining = set(inherited_descriptors)
            while remaining and len(opened) < 512:
                descriptor = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
                opened.append(descriptor)
                remaining.discard(descriptor)
            before_exit_events = len(events)
            manager.__exit__(None, None, None)
            reused_safe = not remaining and all(os.fstat(fd) for fd in opened)
            hooks_skipped = len(events) == before_exit_events
            status = registry + b":" + str(int(reused_safe and hooks_skipped)).encode()
            os.write(write_fd, status)
            os._exit(0)
        except BaseException:
            os.write(write_fd, b"child-error")
            os._exit(2)

    os.close(write_fd)
    try:
        status = os.read(read_fd, 128)
        waited, wait_status = os.waitpid(pid, 0)
        assert waited == pid
        assert os.waitstatus_to_exitcode(wait_status) == 0
        assert status == b"contention:1"
        assert _run_flock(path).returncode == 1
    finally:
        os.close(read_fd)
        manager.__exit__(None, None, None)
    assert _run_flock(path).returncode == 0


def test_parent_release_is_not_retained_by_live_fork_child(tmp_path: Path) -> None:
    pki = _pki(tmp_path)
    path = _lock_file(pki, "lifecycle")
    manager = acquire_pki_locks(pki, "lifecycle", no_state=True)
    manager.__enter__()
    ready_read, ready_write = os.pipe()
    release_read, release_write = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(ready_read)
        os.close(release_write)
        try:
            os.write(ready_write, b"ready")
            if os.read(release_read, 1) != b"x":
                os._exit(2)
            manager.__exit__(None, None, None)
            os._exit(0)
        except BaseException:
            os._exit(3)

    os.close(ready_write)
    os.close(release_read)
    try:
        assert os.read(ready_read, 5) == b"ready"
        manager.__exit__(None, None, None)
        assert os.waitpid(pid, os.WNOHANG) == (0, 0)
        assert _run_flock(path).returncode == 0
        os.write(release_write, b"x")
        waited, wait_status = os.waitpid(pid, 0)
        assert waited == pid
        assert os.waitstatus_to_exitcode(wait_status) == 0
    finally:
        os.close(ready_read)
        os.close(release_write)


def test_lock_descriptors_are_noninheritable_across_exec(tmp_path: Path) -> None:
    pki = _pki(tmp_path)
    _all_lock_files(pki)
    with acquire_pki_locks(pki, "export", no_state=True):
        descriptors = sorted(_pki_descriptors(pki))
        assert len(descriptors) >= len(LOCK_ORDER)
        source = (
            "import os,sys; inherited=[]; "
            "\nfor value in sys.argv[1:]:"
            "\n try: os.fstat(int(value))"
            "\n except OSError: pass"
            "\n else: inherited.append(value)"
            "\nprint(','.join(inherited))"
        )
        result = subprocess.run(
            (PYTHON, "-c", source, *(str(fd) for fd in descriptors)),
            close_fds=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=3,
            check=True,
        )
    assert result.stdout == b"\n"
    assert result.stderr == b""


def test_sigkill_releases_kernel_lock(tmp_path: Path) -> None:
    pki = _pki(tmp_path)
    path = _lock_file(pki, "lifecycle")
    marker = tmp_path / "python-held"
    source = (
        "from pathlib import Path; import signal,sys; "
        "from src.platform_pki.locks import acquire_pki_locks; "
        "\nwith acquire_pki_locks(sys.argv[1], 'lifecycle', no_state=True):"
        "\n Path(sys.argv[2]).write_bytes(b'held'); signal.pause()"
    )
    process = subprocess.Popen(
        (PYTHON, "-c", source, pki, marker),
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    _wait_for_path(marker, process)
    process.kill()
    stdout, stderr = process.communicate(timeout=3)
    assert shell_status(process.returncode) == 137
    assert stdout == stderr == b""
    assert _run_flock(path).returncode == 0


@pytest.mark.parametrize("state", ("missing", "mode", "file", "symlink"))
def test_lock_directory_policy_is_exact(state: str, tmp_path: Path) -> None:
    pki = _pki(tmp_path)
    lock_directory = pki / "locks"
    lock_directory.rmdir()
    if state == "mode":
        lock_directory.mkdir(mode=0o755)
        lock_directory.chmod(0o755)
    elif state == "file":
        lock_directory.write_bytes(b"")
    elif state == "symlink":
        target = tmp_path / "other-locks"
        target.mkdir(mode=0o700)
        lock_directory.symlink_to(target, target_is_directory=True)

    with pytest.raises(LockPolicyError):
        with acquire_pki_locks(pki, "lifecycle"):
            pass
    if state == "missing":
        assert not lock_directory.exists()


def test_raw_integer_parent_and_noncanonical_paths_are_rejected(tmp_path: Path) -> None:
    pki = _pki(tmp_path)
    with pytest.raises(TypeError):
        with acquire_pki_locks(3, "lifecycle"):  # type: ignore[arg-type]
            pass
    with pytest.raises(ApplicationError):
        with acquire_pki_locks(f"{pki}/../secret", "lifecycle"):
            pass


def test_release_failure_is_static_and_close_still_releases_kernel_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pki = _pki(tmp_path)
    path = _lock_file(pki, "lifecycle")
    real_flock = fcntl.flock

    def fail_unlock(descriptor: int, operation: int) -> None:
        if operation == fcntl.LOCK_UN:
            raise OSError("injected unlock failure")
        real_flock(descriptor, operation)

    monkeypatch.setattr(locks.fcntl, "flock", fail_unlock)
    with pytest.raises(LockReleaseError) as caught:
        with acquire_pki_locks(pki, "lifecycle", no_state=True):
            pass
    assert str(caught.value) == "PKI lock could not be released"
    monkeypatch.setattr(locks.fcntl, "flock", real_flock)
    assert _run_flock(path).returncode == 0


def test_body_exception_is_preserved_when_release_also_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pki = _pki(tmp_path)
    path = _lock_file(pki, "lifecycle")
    real_flock = fcntl.flock
    body_error = RuntimeError("body failure")

    def fail_unlock(descriptor: int, operation: int) -> None:
        if operation == fcntl.LOCK_UN:
            raise OSError("injected unlock failure")
        real_flock(descriptor, operation)

    monkeypatch.setattr(locks.fcntl, "flock", fail_unlock)
    with pytest.raises(RuntimeError) as caught:
        with acquire_pki_locks(pki, "lifecycle", no_state=True):
            raise body_error
    assert caught.value is body_error
    assert isinstance(caught.value.__cause__, LockReleaseError)
    monkeypatch.setattr(locks.fcntl, "flock", real_flock)
    assert _run_flock(path).returncode == 0


def test_acquisition_exception_is_preserved_when_descriptor_close_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pki = _pki(tmp_path)
    path = _lock_file(pki, "lifecycle")
    primary = RuntimeError("acquisition hook failure")
    real_close = os.close

    def fail_after_lock_close(descriptor: int) -> None:
        try:
            target = os.readlink(f"/proc/self/fd/{descriptor}")
        except OSError:
            target = ""
        real_close(descriptor)
        if target == os.fspath(path):
            raise OSError("injected close failure")

    def fail_after_open(point: str) -> None:
        if point == "lock-lifecycle-after-open":
            raise primary

    monkeypatch.setattr(locks.os, "close", fail_after_lock_close)
    with pytest.raises(RuntimeError) as caught:
        with acquire_pki_locks(
            pki,
            "lifecycle",
            no_state=True,
            fault_hook=fail_after_open,
        ):
            pass
    assert caught.value is primary
    assert isinstance(caught.value.__cause__, LockReleaseError)


@pytest.mark.parametrize("phase", ("before-release", "after-release"))
def test_release_hook_failures_preserve_lifo_and_release_every_lock(
    phase: str,
    tmp_path: Path,
) -> None:
    pki = _pki(tmp_path)
    _all_lock_files(pki)
    events: list[str] = []
    hook_error = RuntimeError("release hook failure")
    target = f"lock-export-{phase}"

    def failing_hook(point: str) -> None:
        events.append(point)
        if point == target:
            raise hook_error

    with pytest.raises(RuntimeError) as caught:
        with acquire_pki_locks(
            pki,
            "export",
            no_state=True,
            pause_hook=failing_hook,
        ):
            pass
    assert caught.value is hook_error
    before_release = [
        point.removeprefix("lock-").removesuffix("-before-release")
        for point in events
        if point.endswith("-before-release")
    ]
    after_release = [
        point.removeprefix("lock-").removesuffix("-after-release")
        for point in events
        if point.endswith("-after-release")
    ]
    assert before_release == list(reversed(LOCK_ORDER))
    assert after_release == list(reversed(LOCK_ORDER))
    for name in LOCK_ORDER:
        assert _run_flock(pki / "locks" / name).returncode == 0


def test_lock_errors_and_fault_failures_are_static_and_secret_safe(
    tmp_path: Path,
) -> None:
    secret = "operator-secret-path"
    pki = tmp_path / secret
    pki.mkdir(mode=0o700)
    for error_type in (
        LockDuplicateError,
        LockOrderError,
        LockPolicyError,
        LockContentionError,
        LockAcquireError,
        LockReleaseError,
    ):
        error = error_type()
        assert isinstance(error, LockError)
        assert isinstance(error, ApplicationError)
        assert secret not in str(error)
        assert secret not in repr(error)

    point = f"lock-lifecycle-after-pre-stat-{secret}"
    with pytest.raises(ApplicationError) as caught:
        FaultHook(failure_at=point)(point)
    assert secret not in str(caught.value)
    assert secret not in repr(caught.value)
