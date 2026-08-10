from __future__ import annotations

import errno
import os
import stat
import subprocess
import sys
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from src.platform_pki import filesystem
from src.platform_pki.errors import ApplicationError
from src.platform_pki.filesystem import (
    ABSENT,
    DirectoryIdentity,
    DirectoryPolicy,
    FileIdentity,
    FileObjectState,
    FilePolicy,
    FilesystemCloseError,
    FilesystemError,
    FilesystemIdentityError,
    FilesystemLookupError,
    FilesystemPolicyError,
    FilesystemReadLimitError,
    FilesystemSymlinkError,
    FilesystemTraversalError,
    FilesystemTypeError,
    MetadataEntry,
    OpenedDirectory,
    OpenedFile,
    TrustedAncestorError,
    fsync_file,
    fsync_rename_parents,
    identity_at,
    open_trusted_directory,
    open_descendant_file,
    walk_metadata,
)


def test_identity_models_are_exact_distinct_and_immutable(tmp_path: Path) -> None:
    path = tmp_path / "file"
    path.write_bytes(b"payload")
    path.chmod(0o644)
    identity = identity_at(path)
    assert isinstance(identity, FileIdentity)
    assert identity.kind == "regular"
    assert identity.permissions == 0o644
    assert identity.size == 7
    assert identity.state == FileObjectState(
        identity.dev,
        identity.ino,
        identity.uid,
        identity.permissions,
        identity.links,
        identity.size,
        "regular",
    )
    directory_identity = DirectoryIdentity(
        identity.dev,
        identity.ino,
        identity.uid,
        identity.permissions,
        "directory",
    )
    assert directory_identity != identity

    for value, field in (
        (identity, "size"),
        (identity.state, "links"),
        (directory_identity, "ino"),
        (FilePolicy(owner=os.getuid()), "owner"),
        (DirectoryPolicy(mode=0o700), "mode"),
    ):
        with pytest.raises(FrozenInstanceError):
            setattr(value, field, 0)


def test_identity_at_distinguishes_absence_and_rejects_dangling_link(
    tmp_path: Path,
) -> None:
    assert identity_at(tmp_path / "missing") is ABSENT
    dangling = tmp_path / "dangling"
    dangling.symlink_to("missing-target")
    with pytest.raises(FilesystemSymlinkError):
        identity_at(dangling)


def test_identity_at_does_not_treat_estale_as_absence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_stat = os.stat

    def stale_stat(path: str, *args: object, **kwargs: object) -> os.stat_result:
        if path == "entry":
            raise OSError(errno.ESTALE, "stale")
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(filesystem.os, "stat", stale_stat)
    with OpenedDirectory(tmp_path) as parent:
        with pytest.raises(FilesystemLookupError):
            identity_at("entry", dir_fd=parent)


def test_leaf_and_ancestor_symlinks_are_rejected(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    source = real / "source"
    source.write_bytes(b"source")
    leaf = real / "leaf-link"
    leaf.symlink_to(source)
    ancestor = tmp_path / "ancestor-link"
    ancestor.symlink_to(real, target_is_directory=True)

    with pytest.raises(FilesystemSymlinkError):
        OpenedFile(leaf)
    with pytest.raises(FilesystemSymlinkError):
        OpenedFile(ancestor / "source")


def test_unsupported_filesystem_kinds_are_rejected_before_open(tmp_path: Path) -> None:
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    with pytest.raises(FilesystemTypeError):
        identity_at(fifo)
    with pytest.raises(FilesystemTypeError):
        OpenedFile(fifo)


def test_file_policy_rejects_hardlinks_modes_owner_and_size(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.write_bytes(b"1234")
    linked = tmp_path / "linked"
    os.link(source, linked)

    with pytest.raises(FilesystemPolicyError):
        OpenedFile(source, policy=FilePolicy(links=1))
    with pytest.raises(FilesystemPolicyError):
        OpenedFile(source, policy=FilePolicy(mode=0o600))
    with pytest.raises(FilesystemPolicyError):
        OpenedFile(source, policy=FilePolicy(forbidden_bits=0o044))
    with pytest.raises(FilesystemPolicyError):
        OpenedFile(source, policy=FilePolicy(owner=os.getuid() + 1))
    with pytest.raises(FilesystemPolicyError):
        OpenedFile(source, policy=FilePolicy(max_size=3))


def test_directory_policy_and_expected_profiles(tmp_path: Path) -> None:
    directory_path = tmp_path / "private"
    directory_path.mkdir(mode=0o700)
    directory = OpenedDirectory(
        directory_path,
        policy=DirectoryPolicy(owner=os.getuid(), mode=0o700),
    )
    try:
        exact = directory.identity
        state = directory.state
        stable = directory.directory_identity
    finally:
        directory.close()

    for expected in (exact, state, stable):
        with OpenedDirectory(directory_path, expected_identity=expected):
            pass
    with pytest.raises(FilesystemIdentityError):
        OpenedDirectory(
            directory_path,
            expected_identity=DirectoryIdentity(
                stable.dev,
                stable.ino + 1,
                stable.uid,
                stable.permissions,
                "directory",
            ),
        )
    with pytest.raises(FilesystemPolicyError):
        OpenedDirectory(directory_path, policy=DirectoryPolicy(mode=0o755))


def test_directory_open_allows_concurrent_child_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    real_open = filesystem._open_os
    changed = False

    def open_after_child_creation(path: str, flags: int, dir_fd: int | None = None) -> int:
        nonlocal changed
        if path == "target" and not changed:
            (target / "child").write_bytes(b"created concurrently")
            changed = True
        return real_open(path, flags, dir_fd)

    with OpenedDirectory(tmp_path) as parent:
        monkeypatch.setattr(filesystem, "_open_os", open_after_child_creation)
        with parent.open_directory("target"):
            pass
    assert changed


@pytest.mark.parametrize("phase", ("before-open", "after-open"))
def test_directory_open_rejects_same_name_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
) -> None:
    target = tmp_path / "target"
    moved = tmp_path / "moved"
    target.mkdir()
    original_inode = target.stat().st_ino
    real_open = filesystem._open_os
    real_fstat_identity = filesystem._fstat_identity
    replaced = False

    def replace_target() -> None:
        nonlocal replaced
        os.rename(target, moved)
        target.mkdir()
        replaced = True

    def open_with_race(path: str, flags: int, dir_fd: int | None = None) -> int:
        if phase == "before-open" and path == "target" and not replaced:
            replace_target()
        return real_open(path, flags, dir_fd)

    def fstat_with_race(descriptor: int) -> FileIdentity:
        identity = real_fstat_identity(descriptor)
        if phase == "after-open" and identity.ino == original_inode and not replaced:
            replace_target()
        return identity

    with OpenedDirectory(tmp_path) as parent:
        monkeypatch.setattr(filesystem, "_open_os", open_with_race)
        monkeypatch.setattr(filesystem, "_fstat_identity", fstat_with_race)
        with pytest.raises(FilesystemIdentityError):
            parent.open_directory("target")
    assert replaced


def test_opened_file_remains_bound_and_detects_path_replacement(tmp_path: Path) -> None:
    path = tmp_path / "value"
    replacement = tmp_path / "replacement"
    path.write_bytes(b"original")
    replacement.write_bytes(b"replacement")

    with OpenedFile(path) as opened:
        os.replace(replacement, path)
        assert os.pread(opened.fileno(), 32, 0) == b"original"
        with pytest.raises(FilesystemIdentityError):
            opened.read(32)


def test_same_inode_nanosecond_change_fails_final_recheck(tmp_path: Path) -> None:
    path = tmp_path / "value"
    path.write_bytes(b"unchanged")
    with OpenedFile(path) as opened:
        before = opened.identity
        os.utime(
            path,
            ns=(before.mtime_ns + 1_000_003, before.mtime_ns + 1_000_003),
        )
        after = identity_at(path)
        assert isinstance(after, FileIdentity)
        assert (after.dev, after.ino) == (before.dev, before.ino)
        assert after.mtime_ns != before.mtime_ns
        with pytest.raises(FilesystemIdentityError):
            opened.recheck()


def test_bounded_read_accepts_boundary_and_reads_only_limit_plus_one(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "value"
    path.write_bytes(b"12345")
    requests: list[int] = []
    real_pread = os.pread

    def recording_pread(fd: int, size: int, offset: int) -> bytes:
        requests.append(size)
        return real_pread(fd, size, offset)

    monkeypatch.setattr(filesystem.os, "pread", recording_pread)
    with OpenedFile(path) as opened:
        assert opened.read(5) == b"12345"
        with pytest.raises(FilesystemReadLimitError):
            opened.read(4)
    assert max(requests) <= 6
    assert 5 in requests


def test_prefix_read_never_requests_more_than_the_explicit_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "value"
    path.write_bytes(b"header\n" + b"tail" * 100000)
    requests: list[tuple[int, int]] = []
    real_pread = os.pread

    def recording_pread(fd: int, size: int, offset: int) -> bytes:
        requests.append((size, offset))
        return real_pread(fd, size, offset)

    monkeypatch.setattr(filesystem.os, "pread", recording_pread)
    with OpenedFile(path) as opened:
        assert opened.read_prefix(7) == b"header\n"
    assert requests == [(7, 0)]


def test_open_descendant_file_applies_every_directory_policy(tmp_path: Path) -> None:
    root_path = tmp_path / "root"
    child = root_path / "child/private"
    child.mkdir(mode=0o700, parents=True)
    root_path.chmod(0o700)
    (root_path / "child").chmod(0o755)
    path = child / "value"
    path.write_bytes(b"value")
    path.chmod(0o600)
    with OpenedDirectory(root_path) as root:
        with pytest.raises(FilesystemPolicyError):
            open_descendant_file(
                root,
                ("child", "private", "value"),
                directory_policy=DirectoryPolicy(mode=0o700),
                file_policy=FilePolicy(mode=0o600),
            )


def test_metadata_walk_is_descriptor_relative_and_does_not_follow_types(
    tmp_path: Path,
) -> None:
    root_path = tmp_path / "root"
    directory = root_path / "directory"
    directory.mkdir(parents=True)
    (directory / "file").write_bytes(b"content")
    (root_path / "link").symlink_to(directory, target_is_directory=True)
    os.mkfifo(root_path / "fifo")

    entries: tuple[MetadataEntry, ...] = ()
    with OpenedDirectory(root_path) as root:
        entries = tuple(walk_metadata(root))
    assert all(isinstance(entry, MetadataEntry) for entry in entries)
    observed = {entry.relative: entry.kind for entry in entries}
    assert observed == {
        (): "directory",
        ("directory",): "directory",
        ("directory", "file"): "regular",
        ("fifo",): "fifo",
        ("link",): "symlink",
    }
    assert ("link", "file") not in observed


def test_bounded_read_rejects_in_place_change_during_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "value"
    path.write_bytes(b"a" * (filesystem._READ_CHUNK + 1))
    writer = os.open(path, os.O_WRONLY | os.O_CLOEXEC)
    real_pread = os.pread
    changed = False

    def changing_pread(fd: int, size: int, offset: int) -> bytes:
        nonlocal changed
        data = real_pread(fd, size, offset)
        if not changed:
            os.pwrite(writer, b"b", 0)
            changed = True
        return data

    try:
        monkeypatch.setattr(filesystem.os, "pread", changing_pread)
        with OpenedFile(path) as opened:
            with pytest.raises(FilesystemIdentityError):
                opened.read(filesystem._READ_CHUNK + 1)
    finally:
        os.close(writer)


def test_descriptors_are_non_inheritable_and_closed_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "value"
    path.write_bytes(b"value")
    closed: list[int] = []
    real_close = os.close

    def recording_close(fd: int) -> None:
        closed.append(fd)
        real_close(fd)

    opened = OpenedFile(path)
    try:
        descriptor = opened.fileno()
        assert not os.get_inheritable(descriptor)
        monkeypatch.setattr(filesystem.os, "close", recording_close)
    finally:
        opened.close()
    opened.close()
    assert closed.count(descriptor) == 1


def test_close_failure_is_not_retried(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "value"
    path.write_bytes(b"value")
    opened = OpenedFile(path)
    descriptor = opened.fileno()
    attempts: list[int] = []
    real_close = os.close

    def fail_after_close(fd: int) -> None:
        attempts.append(fd)
        real_close(fd)
        if fd == descriptor:
            raise OSError("injected close failure")

    monkeypatch.setattr(filesystem.os, "close", fail_after_close)
    with pytest.raises(FilesystemCloseError):
        opened.close()
    opened.close()
    assert attempts.count(descriptor) == 1


def test_descriptor_is_closed_across_exec_even_when_close_fds_is_disabled(
    tmp_path: Path,
) -> None:
    path = tmp_path / "value"
    path.write_bytes(b"value")
    opened = OpenedFile(path)
    result: subprocess.CompletedProcess[bytes] | None = None
    try:
        descriptor = opened.fileno()
        result = subprocess.run(
            (
                sys.executable,
                "-c",
                (
                    "import os,sys; fd=int(sys.argv[1]); "
                    "\ntry: os.fstat(fd)\n"
                    "except OSError: print('closed')\n"
                    "else: print('inherited')"
                ),
                str(descriptor),
            ),
            check=True,
            close_fds=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    finally:
        opened.close()
    assert result is not None
    assert result.stdout == b"closed\n"
    assert result.stderr == b""


def test_pinned_parent_child_open_ignores_parent_path_replacement(
    tmp_path: Path,
) -> None:
    parent_path = tmp_path / "parent"
    moved_path = tmp_path / "moved"
    parent_path.mkdir()
    (parent_path / "value").write_bytes(b"pinned")

    with OpenedDirectory(parent_path) as parent:
        os.rename(parent_path, moved_path)
        parent_path.mkdir()
        (parent_path / "value").write_bytes(b"redirected")
        with parent.open_file("value") as child:
            parent.close()
            assert os.pread(child.fileno(), 32, 0) == b"pinned"
            with pytest.raises(FilesystemIdentityError):
                child.read(32)


def test_child_names_must_be_single_components(tmp_path: Path) -> None:
    with OpenedDirectory(tmp_path) as directory:
        for name in ("", ".", "..", "child/name"):
            with pytest.raises(ValueError):
                directory.identity_at(name)


def test_child_open_pins_parent_before_concurrent_close(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent_path = tmp_path / "parent"
    parent_path.mkdir()
    (parent_path / "value").write_bytes(b"bound")
    parent = OpenedDirectory(parent_path)
    real_pin = parent._pin_for_child

    def pin_then_close() -> tuple[int, tuple[object, ...]]:
        descriptor, bindings = real_pin()
        parent.close()
        return descriptor, bindings  # type: ignore[return-value]

    monkeypatch.setattr(parent, "_pin_for_child", pin_then_close)
    with parent.open_file("value") as child:
        assert child.read(16) == b"bound"


def test_trusted_traversal_closes_next_directory_when_prior_close_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    child = tmp_path / "child"
    child.mkdir()
    real_close = OpenedDirectory.close
    real_open_directory = OpenedDirectory.open_directory
    next_descriptors: list[int] = []
    injected = False

    def record_open(self: OpenedDirectory, name: str, **kwargs: object) -> OpenedDirectory:
        opened = real_open_directory(self, name, **kwargs)  # type: ignore[arg-type]
        next_descriptors.append(opened.fileno())
        return opened

    def fail_after_close(self: OpenedDirectory) -> None:
        nonlocal injected
        real_close(self)
        if not injected:
            injected = True
            raise FilesystemCloseError()

    monkeypatch.setattr(OpenedDirectory, "open_directory", record_open)
    monkeypatch.setattr(OpenedDirectory, "close", fail_after_close)
    with pytest.raises(FilesystemCloseError):
        open_trusted_directory(child)
    assert next_descriptors
    with pytest.raises(OSError):
        os.fstat(next_descriptors[-1])


def test_fsync_file_and_rename_parent_ordering_and_deduplication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_path = tmp_path / "source"
    destination_path = tmp_path / "destination"
    source_path.mkdir()
    destination_path.mkdir()
    value = source_path / "value"
    value.write_bytes(b"value")
    synced_files: list[int] = []
    real_fsync = os.fsync

    def recording_os_fsync(fd: int) -> None:
        synced_files.append(fd)
        real_fsync(fd)

    with OpenedFile(value) as opened_file:
        monkeypatch.setattr(filesystem.os, "fsync", recording_os_fsync)
        fsync_file(opened_file)
        assert synced_files == [opened_file.fileno()]

    ordering: list[DirectoryIdentity] = []

    def record_directory(directory: OpenedDirectory) -> None:
        ordering.append(directory.directory_identity)

    monkeypatch.setattr(filesystem, "fsync_directory", record_directory)
    with (
        OpenedDirectory(source_path) as source,
        OpenedDirectory(destination_path) as destination,
        OpenedDirectory(source_path) as same_source,
    ):
        fsync_rename_parents(source, destination)
        assert ordering == [source.directory_identity, destination.directory_identity]
        ordering.clear()
        fsync_rename_parents(source, same_source)
        assert ordering == [source.directory_identity]


def test_trusted_traversal_allows_root_current_uid_and_sticky_writable(
    tmp_path: Path,
) -> None:
    sticky = tmp_path / "sticky"
    sticky.mkdir(mode=0o777)
    sticky.chmod(0o1777)
    child = sticky / "child"
    child.mkdir(mode=0o700)

    with open_trusted_directory(child) as opened:
        assert opened.identity.kind == "directory"
        assert opened.identity.uid in (0, os.getuid())


def test_trusted_traversal_rejects_symlink_foreign_owner_and_unsafe_mode(
    tmp_path: Path,
) -> None:
    safe = tmp_path / "safe"
    safe.mkdir(mode=0o700)
    alias = tmp_path / "alias"
    alias.symlink_to(safe, target_is_directory=True)
    with pytest.raises(FilesystemSymlinkError):
        open_trusted_directory(alias)

    unsafe = tmp_path / "unsafe"
    unsafe.mkdir(mode=0o777)
    unsafe.chmod(0o777)
    with pytest.raises(TrustedAncestorError):
        open_trusted_directory(unsafe)

    if os.getuid() != 0:
        with pytest.raises(TrustedAncestorError):
            open_trusted_directory(safe, current_uid=os.getuid() + 1)

    with pytest.raises(FilesystemError):
        open_trusted_directory(tmp_path / "absent")
    with pytest.raises(ValueError):
        open_trusted_directory("relative")


def test_errors_are_structural_safe_application_errors(tmp_path: Path) -> None:
    controlled = tmp_path / "bad\nname"
    controlled.symlink_to("missing")
    with pytest.raises(FilesystemError) as caught:
        identity_at(controlled)
    assert isinstance(caught.value, ApplicationError)
    assert "\n" not in str(caught.value)
    assert "bad" not in str(caught.value)
    assert "bad" not in repr(caught.value)


def test_required_linux_open_flags_are_active() -> None:
    assert filesystem._FILE_FLAGS & os.O_NOFOLLOW
    assert filesystem._FILE_FLAGS & os.O_CLOEXEC
    assert filesystem._DIRECTORY_FLAGS & os.O_DIRECTORY
    assert stat.S_ISDIR(os.stat("/").st_mode)
