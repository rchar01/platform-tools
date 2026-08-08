from __future__ import annotations

import os
import select
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import FrozenInstanceError
from pathlib import Path
from types import SimpleNamespace

import pytest

from src.platform_pki import publication
from src.platform_pki.errors import ApplicationError, render_error, shell_status
from src.platform_pki.faults import FaultHook, InjectedFaultError, PauseHook
from src.platform_pki.filesystem import (
    ABSENT,
    FileIdentity,
    OpenedDirectory,
    OpenedFile,
    identity_at,
)
from src.platform_pki.publication import (
    PUBLICATION_CHECKPOINTS,
    ExchangeResult,
    GuardedExchangeRaceError,
    PublicationAmbiguousError,
    PublicationCleanupAmbiguousError,
    PublicationCleanupError,
    PublicationCrossDeviceError,
    PublicationDestinationExistsError,
    PublicationDurabilityError,
    PublicationError,
    PublicationIdentityError,
    PublicationPolicyError,
    PublicationReplacementAmbiguousError,
    PublicationReplacementCleanupError,
    PublicationResult,
    PublicationStageError,
    PublicationTreeError,
    ReplacementCleanupDisposition,
    ReplacementResult,
    TreeReadiness,
    atomic_write_bytes,
    exchange_exact,
    exchange_guarded_regular_files,
    fsync_tree,
    publish_no_clobber,
    remove_exact_tree,
    replace_exact,
    stage_file_bytes,
    unlink_exact,
)


ROOT = Path(__file__).resolve().parents[1]
PYTHON = sys.executable


def _identity(path: Path) -> FileIdentity:
    identity = identity_at(path)
    assert isinstance(identity, FileIdentity)
    return identity


def _write(path: Path, data: bytes, mode: int = 0o600) -> FileIdentity:
    path.write_bytes(data)
    path.chmod(mode)
    return _identity(path)


def _tree_readiness(
    parent: OpenedDirectory,
    path: Path,
    name: str,
) -> TreeReadiness:
    with OpenedDirectory(path) as root:
        return fsync_tree(root, parent, name)


def _assert_same_tree(actual: TreeReadiness, expected: TreeReadiness) -> None:
    assert actual.root_identity.state == expected.root_identity.state
    assert actual.root_identity.mtime_ns == expected.root_identity.mtime_ns
    assert actual.snapshot == expected.snapshot
    assert actual.root_digest == expected.root_digest


def _different_uid(result: os.stat_result) -> SimpleNamespace:
    return SimpleNamespace(
        st_mode=result.st_mode,
        st_dev=result.st_dev,
        st_ino=result.st_ino,
        st_uid=result.st_uid + 1,
        st_nlink=result.st_nlink,
        st_size=result.st_size,
        st_mtime_ns=result.st_mtime_ns,
        st_ctime_ns=result.st_ctime_ns,
    )


def _fail_second_directory_pin(
    monkeypatch: pytest.MonkeyPatch,
) -> list[publication._PinnedDirectory]:
    real_pin = publication._pin_directory
    pins: list[publication._PinnedDirectory] = []

    def fail_second(source: OpenedDirectory) -> publication._PinnedDirectory:
        if pins:
            raise RuntimeError("injected second pin failure")
        pin = real_pin(source)
        pins.append(pin)
        return pin

    monkeypatch.setattr(publication, "_pin_directory", fail_second)
    return pins


def test_checkpoint_domain_is_finite_unique_and_literal() -> None:
    assert isinstance(PUBLICATION_CHECKPOINTS, tuple)
    assert len(PUBLICATION_CHECKPOINTS) == len(set(PUBLICATION_CHECKPOINTS)) == 48
    assert {
        "stage-before-create",
        "stage-after-write",
        "publication-before-mutation",
        "publication-after-mutation",
        "exchange-before-mutation",
        "exchange-after-mutation",
        "guarded-exchange-before-mutation",
        "guarded-exchange-after-mutation",
        "replacement-before-exchange",
        "replacement-before-final-authorization",
        "replacement-after-exchange-durability",
        "replacement-terminal-validation",
        "cleanup-before-unlink",
        "tree-before-final-validation",
        "tree-cleanup-before-entry-unlink",
        "tree-cleanup-before-directory-rmdir",
        "tree-cleanup-before-root-rmdir",
    } <= set(PUBLICATION_CHECKPOINTS)
    assert all(point == point.strip() and point.isascii() for point in PUBLICATION_CHECKPOINTS)


@pytest.mark.parametrize("data", (b"", b"exact\x00bytes\n", bytes(range(256))))
def test_stage_writes_exact_bytes_mode_owner_and_noninheritable_fd(
    data: bytes,
    tmp_path: Path,
) -> None:
    previous = os.umask(0o777)
    try:
        with OpenedDirectory(tmp_path) as parent:
            stage = stage_file_bytes(parent, "destination", data, mode=0o640)
            try:
                path = tmp_path / stage.name
                assert path.read_bytes() == data
                status = path.stat()
                assert status.st_mode & 0o777 == 0o640
                assert status.st_uid == os.geteuid()
                assert status.st_nlink == 1
                assert not os.get_inheritable(stage.fileno())
                assert _identity(path) == stage.identity
            finally:
                stage.cleanup()
                stage.close()
    finally:
        os.umask(previous)


def test_stage_retries_collisions_without_changing_competitor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    collision = tmp_path / ".target.stage-aaaa"
    collision.write_bytes(b"competitor")
    tokens = iter(("aaaa", "bbbb"))
    monkeypatch.setattr(publication.secrets, "token_hex", lambda _size: next(tokens))
    with OpenedDirectory(tmp_path) as parent:
        stage = stage_file_bytes(parent, "target", b"payload")
        try:
            assert stage.name == ".target.stage-bbbb"
            assert collision.read_bytes() == b"competitor"
        finally:
            stage.cleanup()
            stage.close()


def test_stage_handles_partial_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_write = os.write
    requests: list[int] = []

    def partial_write(fd: int, data: object) -> int:
        view = memoryview(data)  # type: ignore[arg-type]
        requests.append(len(view))
        try:
            return real_write(fd, view[: max(1, min(3, len(view)))])
        finally:
            view.release()

    monkeypatch.setattr(publication.os, "write", partial_write)
    with OpenedDirectory(tmp_path) as parent:
        stage = stage_file_bytes(parent, "target", b"0123456789")
        try:
            assert (tmp_path / stage.name).read_bytes() == b"0123456789"
            assert len(requests) > 1
        finally:
            stage.cleanup()
            stage.close()


def test_stage_failure_removes_only_its_owned_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(publication.os, "write", lambda *_args: 0)
    with OpenedDirectory(tmp_path) as parent:
        with pytest.raises(publication.PublicationStageError):
            stage_file_bytes(parent, "target", b"data")
    assert not tuple(tmp_path.iterdir())


def test_stage_rejects_noncurrent_owner_before_creation(tmp_path: Path) -> None:
    with OpenedDirectory(tmp_path) as parent:
        with pytest.raises(PublicationPolicyError):
            stage_file_bytes(parent, "target", b"data", owner=os.geteuid() + 1)
        with pytest.raises(PublicationPolicyError):
            atomic_write_bytes(parent, "target", b"data", owner=os.geteuid() + 1)
        with pytest.raises(ValueError):
            atomic_write_bytes(parent, "target", b"data", mode=0o200)
    assert not tuple(tmp_path.iterdir())


def test_stage_normalizes_oserror_before_failed_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        publication.os,
        "write",
        lambda *_args: (_ for _ in ()).throw(OSError("secret write")),
    )
    monkeypatch.setattr(
        publication.os,
        "unlink",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("secret unlink")),
    )
    with OpenedDirectory(tmp_path) as parent:
        with pytest.raises(PublicationStageError) as caught:
            stage_file_bytes(parent, "target", b"data")
    assert isinstance(caught.value.__cause__, OSError)
    assert "secret" not in str(caught.value)


def test_stage_terminal_checkpoint_replacement_survives(tmp_path: Path) -> None:
    replacement: Path | None = None

    def replace(point: str) -> None:
        nonlocal replacement
        if point == "stage-after-final-validation":
            staged = next(tmp_path.glob(".target.stage-*"))
            staged.unlink()
            staged.write_bytes(b"competitor")
            staged.chmod(0o600)
            replacement = staged

    with OpenedDirectory(tmp_path) as parent:
        with pytest.raises(PublicationIdentityError):
            stage_file_bytes(parent, "target", b"owned", fault_hook=replace)
    assert replacement is not None
    assert replacement.read_bytes() == b"competitor"


def test_stage_pin_survives_caller_close_and_fd_reuse(tmp_path: Path) -> None:
    parent = OpenedDirectory(tmp_path)
    reused: list[int] = []

    def close_and_reuse(point: str) -> None:
        if point == "stage-before-write":
            parent.close()
            reused.append(os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC))

    try:
        stage = stage_file_bytes(parent, "target", b"payload", fault_hook=close_and_reuse)
        try:
            assert (tmp_path / stage.name).read_bytes() == b"payload"
            stage.cleanup()
        finally:
            stage.close()
    finally:
        parent.close()
        for descriptor in reused:
            os.close(descriptor)


def test_identity_unlink_syncs_parent_and_removes_exact_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "owned"
    expected = _write(path, b"owned")
    synced: list[int] = []
    real_fsync = os.fsync

    def record(fd: int) -> None:
        synced.append(os.fstat(fd).st_ino)
        real_fsync(fd)

    monkeypatch.setattr(publication.os, "fsync", record)
    with OpenedDirectory(tmp_path) as parent:
        parent_inode = parent.identity.ino
        unlink_exact(parent, "owned", expected)
    assert not path.exists()
    assert synced == [parent_inode]


def test_identity_unlink_preserves_checkpoint_replacement(tmp_path: Path) -> None:
    path = tmp_path / "owned"
    expected = _write(path, b"owned")

    def replace(point: str) -> None:
        if point == "cleanup-before-unlink":
            path.unlink()
            path.write_bytes(b"competitor")
            path.chmod(0o600)

    with OpenedDirectory(tmp_path) as parent:
        with pytest.raises(PublicationIdentityError):
            unlink_exact(parent, "owned", expected, fault_hook=replace)
    assert path.read_bytes() == b"competitor"


def test_identity_unlink_rejects_directories_and_hardlinks(tmp_path: Path) -> None:
    directory = tmp_path / "directory"
    directory.mkdir(mode=0o700)
    source = tmp_path / "source"
    linked = tmp_path / "linked"
    _write(source, b"value")
    os.link(source, linked)
    with OpenedDirectory(tmp_path) as parent:
        with pytest.raises(PublicationPolicyError):
            unlink_exact(parent, "directory", _identity(directory))
        with pytest.raises(PublicationPolicyError):
            unlink_exact(parent, "source", _identity(source))
    assert directory.is_dir()
    assert source.exists() and linked.exists()


def test_identity_unlink_pre_mutation_fault_is_not_ambiguous(tmp_path: Path) -> None:
    path = tmp_path / "owned"
    expected = _write(path, b"owned")
    with OpenedDirectory(tmp_path) as parent:
        with pytest.raises(InjectedFaultError) as caught:
            unlink_exact(
                parent,
                "owned",
                expected,
                fault_hook=FaultHook(failure_at="cleanup-before-unlink"),
            )
    assert not isinstance(caught.value, PublicationAmbiguousError)
    assert path.read_bytes() == b"owned"


def test_identity_unlink_post_mutation_fault_is_ambiguous(tmp_path: Path) -> None:
    path = tmp_path / "owned"
    expected = _write(path, b"owned")
    with OpenedDirectory(tmp_path) as parent:
        with pytest.raises(PublicationCleanupAmbiguousError):
            unlink_exact(
                parent,
                "owned",
                expected,
                fault_hook=FaultHook(failure_at="cleanup-after-unlink"),
            )
    assert not path.exists()


def test_identity_unlink_parent_fsync_failure_is_ambiguous_durability(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "owned"
    expected = _write(path, b"owned")
    monkeypatch.setattr(
        publication.os,
        "fsync",
        lambda _fd: (_ for _ in ()).throw(OSError("secret durability")),
    )
    with OpenedDirectory(tmp_path) as parent:
        with pytest.raises(PublicationDurabilityError):
            unlink_exact(parent, "owned", expected)
    assert not path.exists()


def test_atomic_write_is_no_clobber_exact_and_inode_preserving(tmp_path: Path) -> None:
    data = b"\x00exact\xff\n"
    with OpenedDirectory(tmp_path) as parent:
        result = atomic_write_bytes(parent, "published", data, mode=0o640)
    path = tmp_path / "published"
    assert isinstance(result, PublicationResult)
    assert path.read_bytes() == data
    assert path.stat().st_mode & 0o777 == 0o640
    assert path.stat().st_ino == result.identity.ino
    assert not tuple(tmp_path.glob(".published.stage-*"))


@pytest.mark.parametrize("kind", ("file", "directory", "symlink", "dangling"))
def test_atomic_write_rejects_every_existing_destination(
    kind: str,
    tmp_path: Path,
) -> None:
    destination = tmp_path / "destination"
    target = tmp_path / "target"
    if kind == "file":
        _write(destination, b"competitor")
    elif kind == "directory":
        destination.mkdir(mode=0o700)
    elif kind == "symlink":
        _write(target, b"target")
        destination.symlink_to(target)
    else:
        destination.symlink_to("missing")
    before = destination.lstat()
    with OpenedDirectory(tmp_path) as parent:
        with pytest.raises(PublicationDestinationExistsError):
            atomic_write_bytes(parent, "destination", b"new")
    after = destination.lstat()
    assert (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino)
    assert not tuple(tmp_path.glob(".destination.stage-*"))


def test_replace_file_exchanges_exact_inodes_and_removes_old_state(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source_expected = _write(source, b"new", 0o640)
    destination_expected = _write(destination, b"old", 0o600)
    with OpenedDirectory(tmp_path) as parent:
        result = replace_exact(
            parent,
            "source",
            source_expected,
            parent,
            "destination",
            destination_expected,
        )
    assert isinstance(result, ReplacementResult)
    assert result.destination_identity.ino == source_expected.ino
    assert result.old_destination_identity.ino == destination_expected.ino
    assert result.cleanup_disposition is ReplacementCleanupDisposition.REMOVED
    assert result.old_destination_readiness is None
    assert destination.read_bytes() == b"new"
    assert destination.stat().st_ino == source_expected.ino
    assert not source.exists()
    with pytest.raises(FrozenInstanceError):
        result.cleanup_disposition = ReplacementCleanupDisposition.REMOVED  # type: ignore[misc]


def test_replace_emits_only_the_exact_replacement_checkpoint_inventory(
    tmp_path: Path,
) -> None:
    source_expected = _write(tmp_path / "source", b"new")
    destination_expected = _write(tmp_path / "destination", b"old")
    observed: list[str] = []
    with OpenedDirectory(tmp_path) as parent:
        replace_exact(
            parent,
            "source",
            source_expected,
            parent,
            "destination",
            destination_expected,
            fault_hook=observed.append,
        )
    assert observed == [
        "replacement-before-exchange",
        "replacement-before-final-authorization",
        "replacement-after-exchange",
        "replacement-after-exchange-durability",
        "replacement-before-old-disposition",
        "replacement-after-old-disposition",
        "replacement-terminal-validation",
    ]


def test_atomic_write_replaces_only_explicit_exact_destination(tmp_path: Path) -> None:
    destination = tmp_path / "destination"
    expected = _write(destination, b"old")
    wrong = FileIdentity(
        expected.dev,
        expected.ino,
        expected.uid,
        expected.permissions,
        expected.links,
        expected.size + 1,
        expected.mtime_ns,
        expected.ctime_ns,
        expected.kind,
    )
    with OpenedDirectory(tmp_path) as parent:
        with pytest.raises(PublicationIdentityError):
            atomic_write_bytes(
                parent,
                "destination",
                b"rejected",
                expected_destination=wrong,
            )
        assert destination.read_bytes() == b"old"
        result = atomic_write_bytes(
            parent,
            "destination",
            b"new",
            expected_destination=expected,
        )
    assert isinstance(result, ReplacementResult)
    assert destination.read_bytes() == b"new"
    assert not tuple(tmp_path.glob(".destination.stage-*"))
    with OpenedDirectory(tmp_path) as parent:
        with pytest.raises(TypeError):
            atomic_write_bytes(
                parent,
                "other",
                b"data",
                expected_destination=None,
            )
        atomic_write_bytes(parent, "other", b"data", expected_destination=ABSENT)


@pytest.mark.parametrize(
    ("checkpoint", "old_stage_retained"),
    (
        ("replacement-before-old-disposition", True),
        ("replacement-terminal-validation", False),
    ),
)
def test_atomic_write_replacement_preserves_recoverable_ambiguous_state(
    checkpoint: str,
    old_stage_retained: bool,
    tmp_path: Path,
) -> None:
    destination = tmp_path / "destination"
    expected = _write(destination, b"old")
    with OpenedDirectory(tmp_path) as parent:
        with pytest.raises(PublicationAmbiguousError):
            atomic_write_bytes(
                parent,
                "destination",
                b"new",
                expected_destination=expected,
                fault_hook=FaultHook(failure_at=checkpoint),
            )
    assert destination.read_bytes() == b"new"
    stages = tuple(tmp_path.glob(".destination.stage-*"))
    assert bool(stages) is old_stage_retained
    if old_stage_retained:
        assert len(stages) == 1
        assert stages[0].read_bytes() == b"old"
        assert stages[0].stat().st_ino == expected.ino


def test_atomic_write_preserves_primary_over_redacted_cleanup_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "secret-destination"
    expected = _write(destination, b"old-secret")

    def fail_cleanup(_name: str, *, dir_fd: int | None = None) -> None:
        del dir_fd
        raise OSError("secret cleanup diagnostic")

    monkeypatch.setattr(publication.os, "unlink", fail_cleanup)
    with OpenedDirectory(tmp_path) as parent:
        with pytest.raises(InjectedFaultError) as caught:
            atomic_write_bytes(
                parent,
                "secret-destination",
                b"new-secret",
                expected_destination=expected,
                fault_hook=FaultHook(failure_at="replacement-before-exchange"),
            )
    assert isinstance(caught.value.__cause__, PublicationCleanupError)
    assert destination.read_bytes() == b"old-secret"
    stages = tuple(tmp_path.glob(".secret-destination.stage-*"))
    assert len(stages) == 1
    assert stages[0].read_bytes() == b"new-secret"
    rendered = render_error(caught.value)
    for secret in (
        "secret-destination",
        "old-secret",
        "new-secret",
        "secret cleanup diagnostic",
        os.fspath(tmp_path),
    ):
        assert secret not in str(caught.value)
        assert secret not in repr(caught.value)
        assert secret not in str(caught.value.__cause__)
        assert secret not in rendered


def test_replace_directory_retains_complete_old_tree_and_readiness_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir(mode=0o700)
    destination.mkdir(mode=0o700)
    _write(source / "value", b"new")
    child = destination / "child"
    child.mkdir(mode=0o700)
    _write(child / "value", b"old")
    source_expected = _identity(source)
    destination_expected = _identity(destination)
    with OpenedDirectory(tmp_path) as parent:
        with pytest.raises(PublicationPolicyError):
            replace_exact(
                parent,
                "source",
                source_expected,
                parent,
                "destination",
                destination_expected,
            )
        with OpenedDirectory(source) as source_root:
            source_readiness = fsync_tree(source_root, parent, "source")
        with OpenedDirectory(destination) as destination_root:
            destination_readiness = fsync_tree(
                destination_root, parent, "destination"
            )

        def reject_cleanup(*_arguments: object, **_keywords: object) -> None:
            pytest.fail("directory replacement invoked a cleanup syscall")

        monkeypatch.setattr(publication.os, "unlink", reject_cleanup)
        monkeypatch.setattr(publication.os, "rmdir", reject_cleanup)
        result = replace_exact(
            parent,
            "source",
            source_expected,
            parent,
            "destination",
            destination_expected,
            source_readiness=source_readiness,
            destination_readiness=destination_readiness,
        )
    assert result.destination_identity.ino == source_expected.ino
    assert result.old_destination_identity.ino == destination_expected.ino
    assert result.cleanup_disposition is ReplacementCleanupDisposition.RETAINED
    assert result.old_destination_readiness is destination_readiness
    assert (destination / "value").read_bytes() == b"new"
    assert (source / "child/value").read_bytes() == b"old"
    assert source.stat().st_ino == destination_expected.ino
    with OpenedDirectory(tmp_path) as parent:
        retained_readiness = _tree_readiness(parent, source, "source")
    assert retained_readiness.root_identity == result.old_destination_identity
    _assert_same_tree(retained_readiness, destination_readiness)


@pytest.mark.parametrize(
    "checkpoint",
    (
        "replacement-after-exchange",
        "replacement-after-exchange-durability",
        "replacement-before-old-disposition",
        "replacement-after-old-disposition",
        "replacement-terminal-validation",
    ),
)
def test_directory_replacement_fault_retains_both_exact_complete_trees(
    checkpoint: str,
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir(mode=0o700)
    destination.mkdir(mode=0o700)
    source_child = source / "child"
    destination_child = destination / "child"
    source_child.mkdir(mode=0o700)
    destination_child.mkdir(mode=0o700)
    _write(source_child / "value", b"new")
    _write(destination_child / "value", b"old")
    source_expected = _identity(source)
    destination_expected = _identity(destination)
    with OpenedDirectory(tmp_path) as parent:
        source_readiness = _tree_readiness(parent, source, "source")
        destination_readiness = _tree_readiness(
            parent, destination, "destination"
        )
        with pytest.raises(PublicationAmbiguousError):
            replace_exact(
                parent,
                "source",
                source_expected,
                parent,
                "destination",
                destination_expected,
                source_readiness=source_readiness,
                destination_readiness=destination_readiness,
                fault_hook=FaultHook(failure_at=checkpoint),
            )
        retained_old = _tree_readiness(parent, source, "source")
        retained_new = _tree_readiness(parent, destination, "destination")
    _assert_same_tree(retained_old, destination_readiness)
    _assert_same_tree(retained_new, source_readiness)


@pytest.mark.parametrize("race", ("source", "destination"))
def test_replace_pre_exchange_name_races_leave_both_original_names_untouched(
    race: str,
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    retained = tmp_path / f"retained-{race}"
    source_expected = _write(source, b"new")
    destination_expected = _write(destination, b"old")

    def replace(point: str) -> None:
        if point != "replacement-before-exchange":
            return
        path = source if race == "source" else destination
        path.rename(retained)
        _write(path, b"competitor")

    with OpenedDirectory(tmp_path) as parent:
        with pytest.raises(PublicationIdentityError):
            replace_exact(
                parent,
                "source",
                source_expected,
                parent,
                "destination",
                destination_expected,
                fault_hook=replace,
            )
    unchanged = destination if race == "source" else source
    assert unchanged.read_bytes() == (b"old" if race == "source" else b"new")
    assert retained.read_bytes() == (b"new" if race == "source" else b"old")
    assert (source if race == "source" else destination).read_bytes() == b"competitor"


@pytest.mark.parametrize("operand", ("source", "destination"))
def test_replace_syscall_boundary_operand_race_is_ambiguous_and_keeps_all_inodes(
    operand: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    retained = tmp_path / f"retained-{operand}"
    source_expected = _write(source, b"new")
    destination_expected = _write(destination, b"old")
    competitor: FileIdentity | None = None
    real_renameat2 = publication._renameat2

    def race_then_exchange(
        first_parent: publication._PinnedDirectory,
        first_name: str,
        second_parent: publication._PinnedDirectory,
        second_name: str,
        flags: int,
    ) -> None:
        nonlocal competitor
        raced_path = source if operand == "source" else destination
        raced_path.rename(retained)
        competitor = _write(raced_path, f"{operand}-racer".encode())
        real_renameat2(
            first_parent,
            first_name,
            second_parent,
            second_name,
            flags,
        )

    monkeypatch.setattr(publication, "_renameat2", race_then_exchange)
    with OpenedDirectory(tmp_path) as parent:
        with pytest.raises(PublicationAmbiguousError):
            replace_exact(
                parent,
                "source",
                source_expected,
                parent,
                "destination",
                destination_expected,
            )
    assert competitor is not None
    if operand == "source":
        expected_locations = {
            retained: source_expected,
            source: destination_expected,
            destination: competitor,
        }
    else:
        expected_locations = {
            retained: destination_expected,
            source: competitor,
            destination: source_expected,
        }
    for path, expected in expected_locations.items():
        actual = _identity(path)
        assert actual.state == expected.state
        assert actual.mtime_ns == expected.mtime_ns
    assert {path.read_bytes() for path in expected_locations} == {
        b"new",
        b"old",
        f"{operand}-racer".encode(),
    }
    assert set(tmp_path.iterdir()) == set(expected_locations)


@pytest.mark.parametrize("race", ("source-bytes", "destination-mode", "destination-link"))
def test_replace_rejects_same_inode_pre_exchange_mutations(
    race: str,
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source_expected = _write(source, b"new")
    destination_expected = _write(destination, b"old")

    def mutate(point: str) -> None:
        if point != "replacement-before-exchange":
            return
        if race == "source-bytes":
            source.write_bytes(b"NEW")
        elif race == "destination-mode":
            destination.chmod(0o400)
        else:
            os.link(destination, tmp_path / "competitor-link")

    with OpenedDirectory(tmp_path) as parent:
        with pytest.raises(PublicationIdentityError):
            replace_exact(
                parent,
                "source",
                source_expected,
                parent,
                "destination",
                destination_expected,
                fault_hook=mutate,
            )
    assert source.exists() and destination.exists()


@pytest.mark.parametrize(
    ("checkpoint", "source_retained", "error_type"),
    (
        ("replacement-after-exchange", True, PublicationReplacementAmbiguousError),
        (
            "replacement-after-exchange-durability",
            True,
            PublicationReplacementAmbiguousError,
        ),
        (
            "replacement-before-old-disposition",
            True,
            PublicationReplacementAmbiguousError,
        ),
        ("replacement-after-old-disposition", False, PublicationAmbiguousError),
        ("replacement-terminal-validation", False, PublicationAmbiguousError),
    ),
)
def test_replace_checkpoint_failures_preserve_forward_observable_state(
    checkpoint: str,
    source_retained: bool,
    error_type: type[BaseException],
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source_expected = _write(source, b"new")
    destination_expected = _write(destination, b"old")
    with OpenedDirectory(tmp_path) as parent:
        with pytest.raises(error_type):
            replace_exact(
                parent,
                "source",
                source_expected,
                parent,
                "destination",
                destination_expected,
                fault_hook=FaultHook(failure_at=checkpoint),
            )
    assert destination.read_bytes() == b"new"
    assert destination.stat().st_ino == source_expected.ino
    assert source.exists() is source_retained
    if source_retained:
        assert source.read_bytes() == b"old"
        assert source.stat().st_ino == destination_expected.ino


def test_replace_cleanup_failure_and_competitor_are_retained(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source_expected = _write(source, b"new")
    destination_expected = _write(destination, b"old")
    real_unlink = os.unlink

    def fail_old(name: str, *, dir_fd: int | None = None) -> None:
        if name == "source":
            raise OSError("secret cleanup failure")
        real_unlink(name, dir_fd=dir_fd)

    monkeypatch.setattr(publication.os, "unlink", fail_old)
    with OpenedDirectory(tmp_path) as parent:
        with pytest.raises(PublicationReplacementCleanupError) as caught:
            replace_exact(
                parent,
                "source",
                source_expected,
                parent,
                "destination",
                destination_expected,
            )
    assert "secret" not in str(caught.value)
    assert destination.read_bytes() == b"new"
    assert source.read_bytes() == b"old"

    monkeypatch.setattr(publication.os, "unlink", real_unlink)
    source.unlink()
    _write(source, b"competitor")
    assert source.read_bytes() == b"competitor"


def test_replace_cleanup_failure_after_unlink_reports_unconfirmed_durability(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source_expected = _write(source, b"new")
    destination_expected = _write(destination, b"old")
    real_unlink = os.unlink

    def unlink_then_fail(name: str, *, dir_fd: int | None = None) -> None:
        real_unlink(name, dir_fd=dir_fd)
        if name == "source":
            raise OSError("secret post-unlink failure")

    monkeypatch.setattr(publication.os, "unlink", unlink_then_fail)
    with OpenedDirectory(tmp_path) as parent:
        with pytest.raises(PublicationDurabilityError) as caught:
            replace_exact(
                parent,
                "source",
                source_expected,
                parent,
                "destination",
                destination_expected,
            )
    assert "secret" not in str(caught.value)
    assert destination.read_bytes() == b"new"
    assert not source.exists()


def test_replace_cleanup_checkpoint_preserves_competing_source_name(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    retained = tmp_path / "retained-old"
    source_expected = _write(source, b"new")
    destination_expected = _write(destination, b"old")

    def compete(point: str) -> None:
        if point == "replacement-before-old-disposition":
            source.rename(retained)
            _write(source, b"competitor")

    with OpenedDirectory(tmp_path) as parent:
        with pytest.raises(PublicationAmbiguousError):
            replace_exact(
                parent,
                "source",
                source_expected,
                parent,
                "destination",
                destination_expected,
                fault_hook=compete,
            )
    assert destination.read_bytes() == b"new"
    assert retained.read_bytes() == b"old"
    assert source.read_bytes() == b"competitor"


@pytest.mark.parametrize("mutation", ("bytes", "size", "mode", "owner", "link"))
def test_replace_rejects_same_inode_post_exchange_destination_mutation(
    mutation: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source_expected = _write(source, b"new")
    destination_expected = _write(destination, b"old")
    changed = False
    owner_changed = False
    real_fstat = os.fstat

    def observe_owner(fd: int):
        result = real_fstat(fd)
        if owner_changed and result.st_ino == source_expected.ino:
            return _different_uid(result)
        return result

    monkeypatch.setattr(publication.os, "fstat", observe_owner)

    def mutate(point: str) -> None:
        nonlocal changed, owner_changed
        if point != "replacement-before-old-disposition" or changed:
            return
        changed = True
        if mutation == "bytes":
            destination.write_bytes(b"NEW")
        elif mutation == "size":
            with destination.open("ab") as stream:
                stream.write(b"!")
        elif mutation == "mode":
            destination.chmod(0o400)
        elif mutation == "owner":
            owner_changed = True
        else:
            os.link(destination, tmp_path / "retained-link")

    with OpenedDirectory(tmp_path) as parent:
        with pytest.raises(PublicationAmbiguousError):
            replace_exact(
                parent,
                "source",
                source_expected,
                parent,
                "destination",
                destination_expected,
                fault_hook=mutate,
            )
    assert source.read_bytes() == b"old"
    assert destination.stat().st_ino == source_expected.ino


def test_replace_directory_rechecks_nested_state_after_before_exchange_hook(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir(mode=0o700)
    destination.mkdir(mode=0o700)
    _write(source / "value", b"new")
    _write(destination / "value", b"old")
    source_expected = _identity(source)
    destination_expected = _identity(destination)

    def mutate(point: str) -> None:
        if point == "replacement-before-exchange":
            (destination / "value").write_bytes(b"OLD")

    with OpenedDirectory(tmp_path) as parent:
        with OpenedDirectory(source) as source_root:
            source_readiness = fsync_tree(source_root, parent, "source")
        with OpenedDirectory(destination) as destination_root:
            destination_readiness = fsync_tree(
                destination_root, parent, "destination"
            )
        with pytest.raises(PublicationTreeError):
            replace_exact(
                parent,
                "source",
                source_expected,
                parent,
                "destination",
                destination_expected,
                source_readiness=source_readiness,
                destination_readiness=destination_readiness,
                fault_hook=mutate,
            )
    assert (source / "value").read_bytes() == b"new"
    assert (destination / "value").read_bytes() == b"OLD"
    assert source.stat().st_ino == source_expected.ino
    assert destination.stat().st_ino == destination_expected.ino


def test_replace_post_exchange_destination_competitor_is_not_overwritten(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    retained_new = tmp_path / "retained-new"
    source_expected = _write(source, b"new")
    destination_expected = _write(destination, b"old")

    def compete(point: str) -> None:
        if point == "replacement-after-exchange":
            destination.rename(retained_new)
            _write(destination, b"competitor")

    with OpenedDirectory(tmp_path) as parent:
        with pytest.raises(PublicationAmbiguousError):
            replace_exact(
                parent,
                "source",
                source_expected,
                parent,
                "destination",
                destination_expected,
                fault_hook=compete,
            )
    assert retained_new.read_bytes() == b"new"
    assert destination.read_bytes() == b"competitor"
    assert source.read_bytes() == b"old"


def test_replace_cross_parent_same_device_syncs_and_cleans_source_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_parent_path = tmp_path / "source-parent"
    destination_parent_path = tmp_path / "destination-parent"
    source_parent_path.mkdir()
    destination_parent_path.mkdir()
    source_expected = _write(source_parent_path / "source", b"new")
    destination_expected = _write(destination_parent_path / "destination", b"old")
    order: list[int] = []
    real_fsync = os.fsync

    def record(fd: int) -> None:
        order.append(os.fstat(fd).st_ino)
        real_fsync(fd)

    monkeypatch.setattr(publication.os, "fsync", record)
    with (
        OpenedDirectory(source_parent_path) as source_parent,
        OpenedDirectory(destination_parent_path) as destination_parent,
    ):
        source_parent_inode = source_parent.identity.ino
        destination_parent_inode = destination_parent.identity.ino
        replace_exact(
            source_parent,
            "source",
            source_expected,
            destination_parent,
            "destination",
            destination_expected,
        )
    assert order == [
        source_expected.ino,
        destination_expected.ino,
        source_parent_inode,
        destination_parent_inode,
        source_parent_inode,
    ]
    assert not (source_parent_path / "source").exists()
    assert (destination_parent_path / "destination").read_bytes() == b"new"


@pytest.mark.parametrize(("directory_sync", "source_retained"), ((1, True), (2, False)))
def test_replace_parent_fsync_failures_report_durable_ambiguity(
    directory_sync: int,
    source_retained: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source_expected = _write(source, b"new")
    destination_expected = _write(destination, b"old")
    real_fsync = os.fsync
    seen = 0

    def fail_selected(fd: int) -> None:
        nonlocal seen
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            seen += 1
            if seen == directory_sync:
                raise OSError("secret durability failure")
        real_fsync(fd)

    monkeypatch.setattr(publication.os, "fsync", fail_selected)
    with OpenedDirectory(tmp_path) as parent:
        with pytest.raises(PublicationDurabilityError) as caught:
            replace_exact(
                parent,
                "source",
                source_expected,
                parent,
                "destination",
                destination_expected,
            )
    assert "secret" not in str(caught.value)
    assert destination.read_bytes() == b"new"
    assert source.exists() is source_retained
    if source_retained:
        assert source.read_bytes() == b"old"


@pytest.mark.parametrize("unsafe", ("mixed-kind", "source-mode", "destination-link"))
def test_replace_rejects_kind_mode_and_link_policy_before_exchange(
    unsafe: str,
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source_expected = _write(source, b"new")
    if unsafe == "mixed-kind":
        destination.mkdir(mode=0o700)
    else:
        destination_expected = _write(destination, b"old")
        if unsafe == "source-mode":
            source.chmod(0o622)
            source_expected = _identity(source)
        else:
            os.link(destination, tmp_path / "destination-link")
            destination_expected = _identity(destination)
    destination_expected = _identity(destination)
    with OpenedDirectory(tmp_path) as parent:
        with pytest.raises(PublicationPolicyError):
            replace_exact(
                parent,
                "source",
                source_expected,
                parent,
                "destination",
                destination_expected,
            )
    assert source.exists() and destination.exists()


def test_replace_pins_survive_caller_close_and_descriptor_reuse(tmp_path: Path) -> None:
    source_parent_path = tmp_path / "source-parent"
    destination_parent_path = tmp_path / "destination-parent"
    source_parent_path.mkdir()
    destination_parent_path.mkdir()
    source_expected = _write(source_parent_path / "source", b"new")
    destination_expected = _write(destination_parent_path / "destination", b"old")
    source_parent = OpenedDirectory(source_parent_path)
    destination_parent = OpenedDirectory(destination_parent_path)
    reused: list[int] = []

    def close_and_reuse(point: str) -> None:
        if point == "replacement-before-exchange":
            source_parent.close()
            destination_parent.close()
            reused.extend(
                os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC) for _ in range(2)
            )

    try:
        replace_exact(
            source_parent,
            "source",
            source_expected,
            destination_parent,
            "destination",
            destination_expected,
            fault_hook=close_and_reuse,
        )
    finally:
        source_parent.close()
        destination_parent.close()
        for descriptor in reused:
            os.close(descriptor)
    assert not (source_parent_path / "source").exists()
    assert (destination_parent_path / "destination").read_bytes() == b"new"


def test_replacement_retry_does_not_infer_or_mutate_post_exchange_state(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source_expected = _write(source, b"new")
    destination_expected = _write(destination, b"old")
    with OpenedDirectory(tmp_path) as parent:
        with pytest.raises(PublicationReplacementAmbiguousError):
            replace_exact(
                parent,
                "source",
                source_expected,
                parent,
                "destination",
                destination_expected,
                fault_hook=FaultHook(failure_at="replacement-before-old-disposition"),
            )
        with pytest.raises(PublicationIdentityError):
            replace_exact(
                parent,
                "source",
                source_expected,
                parent,
                "destination",
                destination_expected,
            )
    assert source.read_bytes() == b"old"
    assert destination.read_bytes() == b"new"


def test_no_clobber_directory_preserves_exact_inode_and_tree(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir(mode=0o700)
    _write(source / "value", b"tree")
    expected = _identity(source)
    with OpenedDirectory(tmp_path) as parent:
        with OpenedDirectory(source) as root:
            readiness = fsync_tree(root, parent, "source")
        result = publish_no_clobber(
            parent,
            "source",
            expected,
            parent,
            "destination",
            readiness=readiness,
        )
    assert not source.exists()
    assert (tmp_path / "destination/value").read_bytes() == b"tree"
    assert result.identity.ino == expected.ino == (tmp_path / "destination").stat().st_ino


def test_opt_in_tree_readiness_snapshots_symlinks_without_following_them(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    victim = tmp_path / "victim"
    tree.mkdir(mode=0o700)
    victim.write_bytes(b"victim")
    (tree / "link").symlink_to(victim)
    with OpenedDirectory(tmp_path) as parent, OpenedDirectory(tree) as root:
        with pytest.raises(PublicationTreeError):
            fsync_tree(root, parent, "tree")
        readiness = fsync_tree(root, parent, "tree", allow_symlinks=True)
    assert readiness.allows_symlinks
    assert victim.read_bytes() == b"victim"


def test_displaced_tree_cleanup_unlinks_symlinks_without_touching_targets(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    victim = tmp_path / "victim"
    tree.mkdir(mode=0o700)
    victim.mkdir()
    _write(victim / "sentinel", b"victim")
    (tree / "link").symlink_to(victim, target_is_directory=True)
    with OpenedDirectory(tmp_path) as parent, OpenedDirectory(tree) as root:
        readiness = fsync_tree(root, parent, "tree", allow_symlinks=True)
        identity = root.identity
    with OpenedDirectory(tmp_path) as parent:
        remove_exact_tree(parent, "tree", identity, readiness)
    assert not tree.exists()
    assert (victim / "sentinel").read_bytes() == b"victim"


def test_displaced_tree_cleanup_preserves_regular_replacement_before_unlink(
    tmp_path: Path,
) -> None:
    tree = tmp_path / "recovery"
    tree.mkdir(mode=0o700)
    original = _write(tree / "value", b"original")
    with OpenedDirectory(tmp_path) as parent, OpenedDirectory(tree) as root:
        readiness = fsync_tree(root, parent, "recovery")
        identity = root.identity

    saved = tmp_path / "saved-original"

    def replace(point: str) -> None:
        if point != "tree-cleanup-before-entry-unlink":
            return
        (tree / "value").rename(saved)
        _write(tree / "value", b"replacement")

    with OpenedDirectory(tmp_path) as parent:
        with pytest.raises(PublicationReplacementCleanupError):
            remove_exact_tree(
                parent,
                "recovery",
                identity,
                readiness,
                pause_hook=replace,
            )

    assert tree.is_dir()
    assert (tree / "value").read_bytes() == b"replacement"
    assert saved.read_bytes() == b"original"
    assert _identity(saved).ino == original.ino


def test_displaced_tree_cleanup_preserves_nested_replacement_before_rmdir(
    tmp_path: Path,
) -> None:
    tree = tmp_path / "recovery"
    nested = tree / "nested"
    nested.mkdir(mode=0o700, parents=True)
    _write(nested / "old", b"old")
    with OpenedDirectory(tmp_path) as parent, OpenedDirectory(tree) as root:
        readiness = fsync_tree(root, parent, "recovery")
        identity = root.identity

    saved = tmp_path / "saved-nested"

    def replace(point: str) -> None:
        if point != "tree-cleanup-before-directory-rmdir":
            return
        nested.rename(saved)
        nested.mkdir(mode=0o700)
        _write(nested / "victim", b"replacement")

    with OpenedDirectory(tmp_path) as parent:
        with pytest.raises(PublicationReplacementCleanupError):
            remove_exact_tree(
                parent,
                "recovery",
                identity,
                readiness,
                pause_hook=replace,
            )

    assert tree.is_dir()
    assert (nested / "victim").read_bytes() == b"replacement"
    assert saved.is_dir()


def test_displaced_tree_cleanup_preserves_root_replacement_before_rmdir(
    tmp_path: Path,
) -> None:
    recovery = tmp_path / "recovery"
    replacement = tmp_path / "replacement"
    saved = tmp_path / "saved-recovery"
    recovery.mkdir(mode=0o700)
    replacement.mkdir(mode=0o700)
    _write(replacement / "victim", b"replacement")
    with OpenedDirectory(tmp_path) as parent, OpenedDirectory(recovery) as root:
        readiness = fsync_tree(root, parent, "recovery")
        identity = root.identity

    def exchange(point: str) -> None:
        if point != "tree-cleanup-before-root-rmdir":
            return
        recovery.rename(saved)
        replacement.rename(recovery)

    with OpenedDirectory(tmp_path) as parent:
        with pytest.raises(PublicationReplacementCleanupError):
            remove_exact_tree(
                parent,
                "recovery",
                identity,
                readiness,
                pause_hook=exchange,
            )

    assert (recovery / "victim").read_bytes() == b"replacement"
    assert saved.is_dir()
    assert saved.stat().st_ino == identity.ino


def test_directory_publication_requires_exact_parent_bound_readiness(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir(mode=0o700)
    value = source / "value"
    _write(value, b"tree")
    expected = _identity(source)
    with OpenedDirectory(tmp_path) as parent:
        with pytest.raises(PublicationPolicyError):
            publish_no_clobber(parent, "source", expected, parent, "destination")
        with OpenedDirectory(source) as root:
            readiness = fsync_tree(root, parent, "source")
        value.write_bytes(b"changed")
        with pytest.raises(PublicationTreeError):
            publish_no_clobber(
                parent,
                "source",
                expected,
                parent,
                "destination",
                readiness=readiness,
            )
    assert source.is_dir()
    assert not (tmp_path / "destination").exists()


@pytest.mark.parametrize("checkpoint", (
    "publication-before-final-validation",
    "publication-after-final-validation",
))
@pytest.mark.parametrize("mutation", ("nested-bytes", "root-mode"))
def test_directory_publication_rejects_post_mutation_tree_changes(
    checkpoint: str,
    mutation: str,
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir(mode=0o700)
    _write(source / "value", b"original")
    expected = _identity(source)
    changed = False

    def mutate(point: str) -> None:
        nonlocal changed
        if point != checkpoint or changed:
            return
        changed = True
        if mutation == "nested-bytes":
            (destination / "value").write_bytes(b"changed!")
        else:
            destination.chmod(0o500)

    with OpenedDirectory(tmp_path) as parent:
        with OpenedDirectory(source) as root:
            readiness = fsync_tree(root, parent, "source")
        with pytest.raises(PublicationAmbiguousError):
            publish_no_clobber(
                parent,
                "source",
                expected,
                parent,
                "destination",
                readiness=readiness,
                fault_hook=mutate,
            )
    assert destination.is_dir()


def test_no_clobber_rejects_source_and_destination_checkpoint_races(
    tmp_path: Path,
) -> None:
    for race in ("source", "destination"):
        case = tmp_path / race
        case.mkdir()
        source = case / "source"
        expected = _write(source, b"source")

        def compete(point: str, *, race: str = race, case: Path = case) -> None:
            if point != "publication-before-mutation":
                return
            if race == "source":
                source.unlink()
                _write(source, b"replacement")
            else:
                _write(case / "destination", b"competitor")

        with OpenedDirectory(case) as parent:
            expected_error = (
                PublicationIdentityError
                if race == "source"
                else PublicationDestinationExistsError
            )
            with pytest.raises(expected_error):
                publish_no_clobber(
                    parent,
                    "source",
                    expected,
                    parent,
                    "destination",
                    fault_hook=compete,
                )
        assert not (case / "destination").exists() or race == "destination"


def test_no_clobber_rejects_canonical_parent_replacement(tmp_path: Path) -> None:
    parent_path = tmp_path / "parent"
    moved = tmp_path / "moved"
    parent_path.mkdir()
    expected = _write(parent_path / "source", b"source")

    def replace_parent(point: str) -> None:
        if point == "publication-before-mutation":
            parent_path.rename(moved)
            parent_path.mkdir()

    with OpenedDirectory(parent_path) as parent:
        with pytest.raises(PublicationIdentityError):
            publish_no_clobber(
                parent,
                "source",
                expected,
                parent,
                "destination",
                fault_hook=replace_parent,
            )
    assert (moved / "source").read_bytes() == b"source"
    assert not (moved / "destination").exists()


def test_publication_pins_survive_caller_close_and_fd_reuse(tmp_path: Path) -> None:
    source_parent_path = tmp_path / "source-parent"
    destination_parent_path = tmp_path / "destination-parent"
    source_parent_path.mkdir()
    destination_parent_path.mkdir()
    expected = _write(source_parent_path / "source", b"payload")
    source_parent = OpenedDirectory(source_parent_path)
    destination_parent = OpenedDirectory(destination_parent_path)
    reused: list[int] = []

    def close_and_reuse(point: str) -> None:
        if point == "publication-before-mutation":
            source_parent.close()
            destination_parent.close()
            reused.extend(
                os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC) for _ in range(2)
            )

    try:
        publish_no_clobber(
            source_parent,
            "source",
            expected,
            destination_parent,
            "destination",
            fault_hook=close_and_reuse,
        )
    finally:
        source_parent.close()
        destination_parent.close()
        for descriptor in reused:
            os.close(descriptor)
    assert (destination_parent_path / "destination").read_bytes() == b"payload"


def test_publication_closes_source_pin_when_destination_pin_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_path = tmp_path / "source-parent"
    destination_path = tmp_path / "destination-parent"
    source_path.mkdir()
    destination_path.mkdir()
    expected = _write(source_path / "source", b"payload")
    pins = _fail_second_directory_pin(monkeypatch)
    with (
        OpenedDirectory(source_path) as source_parent,
        OpenedDirectory(destination_path) as destination_parent,
    ):
        with pytest.raises(RuntimeError, match="injected second pin failure"):
            publish_no_clobber(
                source_parent,
                "source",
                expected,
                destination_parent,
                "destination",
            )
    assert len(pins) == 1
    with pytest.raises(PublicationIdentityError):
        pins[0].fileno()


def test_no_clobber_syncs_source_then_destination_parent_and_deduplicates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_parent_path = tmp_path / "source-parent"
    destination_parent_path = tmp_path / "destination-parent"
    source_parent_path.mkdir()
    destination_parent_path.mkdir()
    expected = _write(source_parent_path / "source", b"source")
    order: list[int] = []
    real_fsync = os.fsync

    def record(fd: int) -> None:
        order.append(os.fstat(fd).st_ino)
        real_fsync(fd)

    monkeypatch.setattr(publication.os, "fsync", record)
    with (
        OpenedDirectory(source_parent_path) as source_parent,
        OpenedDirectory(destination_parent_path) as destination_parent,
    ):
        source_inode = source_parent.identity.ino
        destination_inode = destination_parent.identity.ino
        publish_no_clobber(
            source_parent,
            "source",
            expected,
            destination_parent,
            "destination",
        )
    assert order == [expected.ino, source_inode, destination_inode]

    same = tmp_path / "same"
    same.mkdir()
    expected = _write(same / "source", b"source")
    order.clear()
    with OpenedDirectory(same) as parent:
        inode = parent.identity.ino
        publish_no_clobber(parent, "source", expected, parent, "destination")
    assert order == [expected.ino, inode]


def test_parent_fsync_failure_retains_published_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with OpenedDirectory(tmp_path) as parent:
        stage = stage_file_bytes(parent, "destination", b"payload")
        real_fsync = os.fsync

        def fail_directory(fd: int) -> None:
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError("secret fsync failure")
            real_fsync(fd)

        monkeypatch.setattr(publication.os, "fsync", fail_directory)
        with pytest.raises(PublicationDurabilityError):
            publish_no_clobber(
                parent,
                stage.name,
                stage.identity,
                parent,
                "destination",
            )
        stage.mark_consumed()
        stage.close()
    assert (tmp_path / "destination").read_bytes() == b"payload"
    assert not (tmp_path / stage.name).exists()


def test_post_mutation_fault_retains_state_and_never_claims_rollback(tmp_path: Path) -> None:
    source = tmp_path / "source"
    expected = _write(source, b"payload")
    with OpenedDirectory(tmp_path) as parent:
        with pytest.raises(PublicationAmbiguousError):
            publish_no_clobber(
                parent,
                "source",
                expected,
                parent,
                "destination",
                fault_hook=FaultHook(failure_at="publication-after-mutation"),
            )
    assert not source.exists()
    assert (tmp_path / "destination").read_bytes() == b"payload"


def test_terminal_publication_checkpoint_replacement_is_ambiguous_and_retained(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    retained = tmp_path / "retained-original"
    expected = _write(source, b"payload")

    def replace(point: str) -> None:
        if point == "publication-after-final-validation":
            destination.rename(retained)
            _write(destination, b"competitor")

    with OpenedDirectory(tmp_path) as parent:
        with pytest.raises(PublicationAmbiguousError):
            publish_no_clobber(
                parent,
                "source",
                expected,
                parent,
                "destination",
                fault_hook=replace,
            )
    assert retained.read_bytes() == b"payload"
    assert destination.read_bytes() == b"competitor"


@pytest.mark.parametrize("checkpoint", (
    "publication-before-final-validation",
    "publication-after-final-validation",
))
@pytest.mark.parametrize("mutation", ("bytes", "size", "mode", "owner", "link"))
def test_publication_rejects_same_inode_post_mutation_changes(
    checkpoint: str,
    mutation: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    expected = _write(source, b"payload")
    changed = False
    owner_changed = False
    real_fstat = os.fstat

    def observe_owner(fd: int):
        result = real_fstat(fd)
        if owner_changed and result.st_ino == expected.ino:
            return _different_uid(result)
        return result

    monkeypatch.setattr(publication.os, "fstat", observe_owner)

    def mutate(point: str) -> None:
        nonlocal changed, owner_changed
        if point != checkpoint or changed:
            return
        changed = True
        if mutation == "bytes":
            destination.write_bytes(b"PAYLOAD")
        elif mutation == "size":
            with destination.open("ab") as stream:
                stream.write(b"!")
        elif mutation == "mode":
            destination.chmod(0o400)
        elif mutation == "owner":
            owner_changed = True
        else:
            os.link(destination, tmp_path / "retained-link")

    with OpenedDirectory(tmp_path) as parent:
        with pytest.raises(PublicationAmbiguousError):
            publish_no_clobber(
                parent,
                "source",
                expected,
                parent,
                "destination",
                fault_hook=mutate,
            )
    assert destination.stat().st_ino == expected.ino


def test_exchange_files_preserves_names_and_swaps_exact_inodes(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    first_expected = _write(first, b"first")
    second_expected = _write(second, b"second")
    with OpenedDirectory(tmp_path) as parent:
        result = exchange_exact(
            parent,
            "first",
            first_expected,
            parent,
            "second",
            second_expected,
        )
    assert isinstance(result, ExchangeResult)
    assert first.read_bytes() == b"second"
    assert second.read_bytes() == b"first"
    assert first.stat().st_ino == result.first_identity.ino == second_expected.ino
    assert second.stat().st_ino == result.second_identity.ino == first_expected.ino


def _guarded_exchange_inputs(
    tmp_path: Path,
) -> tuple[FileIdentity, FileIdentity]:
    stage_expected = _write(tmp_path / "stage", b"new")
    _write(tmp_path / "destination", b"old")
    os.link(tmp_path / "destination", tmp_path / "guard")
    return stage_expected, _identity(tmp_path / "destination")


def test_guarded_exchange_swaps_stage_and_destination_with_guard_intact(
    tmp_path: Path,
) -> None:
    stage_expected, guarded_expected = _guarded_exchange_inputs(tmp_path)
    with OpenedDirectory(tmp_path) as parent:
        result = exchange_guarded_regular_files(
            parent,
            "stage",
            stage_expected,
            "destination",
            guarded_expected,
            "guard",
            guarded_expected,
        )
    assert result.first_identity.ino == guarded_expected.ino
    assert result.second_identity.ino == stage_expected.ino
    assert (tmp_path / "stage").read_bytes() == b"old"
    assert (tmp_path / "destination").read_bytes() == b"new"
    assert (tmp_path / "guard").stat().st_ino == guarded_expected.ino


def test_guarded_exchange_pre_mutation_race_does_not_exchange(tmp_path: Path) -> None:
    stage_expected, guarded_expected = _guarded_exchange_inputs(tmp_path)

    def compete(point: str) -> None:
        if point == "guarded-exchange-before-mutation":
            (tmp_path / "destination").unlink()
            _write(tmp_path / "destination", b"competitor")

    with OpenedDirectory(tmp_path) as parent:
        with pytest.raises(PublicationIdentityError):
            exchange_guarded_regular_files(
                parent,
                "stage",
                stage_expected,
                "destination",
                guarded_expected,
                "guard",
                guarded_expected,
                fault_hook=compete,
            )
    assert (tmp_path / "stage").read_bytes() == b"new"
    assert (tmp_path / "destination").read_bytes() == b"competitor"
    assert (tmp_path / "guard").read_bytes() == b"old"


def test_guarded_exchange_restores_syscall_boundary_destination_race(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stage_expected, guarded_expected = _guarded_exchange_inputs(tmp_path)
    retained = tmp_path / "retained-old"
    real_renameat2 = publication._renameat2
    calls = 0

    def race_then_exchange(
        first_parent: publication._PinnedDirectory,
        first_name: str,
        second_parent: publication._PinnedDirectory,
        second_name: str,
        flags: int,
    ) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            (tmp_path / "destination").rename(retained)
            _write(tmp_path / "destination", b"competitor")
        real_renameat2(
            first_parent,
            first_name,
            second_parent,
            second_name,
            flags,
        )

    monkeypatch.setattr(publication, "_renameat2", race_then_exchange)
    with OpenedDirectory(tmp_path) as parent:
        with pytest.raises(GuardedExchangeRaceError):
            exchange_guarded_regular_files(
                parent,
                "stage",
                stage_expected,
                "destination",
                guarded_expected,
                "guard",
                guarded_expected,
            )
    assert calls == 2
    assert (tmp_path / "stage").read_bytes() == b"new"
    assert (tmp_path / "destination").read_bytes() == b"competitor"
    assert retained.read_bytes() == b"old"
    assert (tmp_path / "guard").stat().st_ino == retained.stat().st_ino


def test_guarded_exchange_post_mutation_fault_retains_swapped_names(
    tmp_path: Path,
) -> None:
    stage_expected, guarded_expected = _guarded_exchange_inputs(tmp_path)
    with OpenedDirectory(tmp_path) as parent:
        with pytest.raises(PublicationAmbiguousError):
            exchange_guarded_regular_files(
                parent,
                "stage",
                stage_expected,
                "destination",
                guarded_expected,
                "guard",
                guarded_expected,
                fault_hook=FaultHook(
                    failure_at="guarded-exchange-after-mutation"
                ),
            )
    assert (tmp_path / "stage").read_bytes() == b"old"
    assert (tmp_path / "destination").read_bytes() == b"new"
    assert (tmp_path / "guard").read_bytes() == b"old"


def test_exchange_directories_preserves_both_names(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir(mode=0o700)
    second.mkdir(mode=0o700)
    _write(first / "value", b"first")
    _write(second / "value", b"second")
    first_expected = _identity(first)
    second_expected = _identity(second)
    with OpenedDirectory(tmp_path) as parent:
        with OpenedDirectory(first) as first_root:
            first_readiness = fsync_tree(first_root, parent, "first")
        with OpenedDirectory(second) as second_root:
            second_readiness = fsync_tree(second_root, parent, "second")
        exchange_exact(
            parent,
            "first",
            first_expected,
            parent,
            "second",
            second_expected,
            first_readiness=first_readiness,
            second_readiness=second_readiness,
        )
    assert (first / "value").read_bytes() == b"second"
    assert (second / "value").read_bytes() == b"first"


def test_exchange_directories_requires_readiness_for_both_operands(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir(mode=0o700)
    second.mkdir(mode=0o700)
    with OpenedDirectory(tmp_path) as parent:
        with pytest.raises(PublicationPolicyError):
            exchange_exact(
                parent,
                "first",
                _identity(first),
                parent,
                "second",
                _identity(second),
            )


@pytest.mark.parametrize("mutation", ("nested-bytes", "root-mode"))
def test_directory_exchange_rejects_post_mutation_tree_changes(
    mutation: str,
    tmp_path: Path,
) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir(mode=0o700)
    second.mkdir(mode=0o700)
    _write(first / "value", b"first!")
    _write(second / "value", b"second")
    first_expected = _identity(first)
    second_expected = _identity(second)

    def mutate(point: str) -> None:
        if point != "exchange-before-final-validation":
            return
        if mutation == "nested-bytes":
            (first / "value").write_bytes(b"SECOND")
        else:
            first.chmod(0o500)

    with OpenedDirectory(tmp_path) as parent:
        with OpenedDirectory(first) as first_root:
            first_readiness = fsync_tree(first_root, parent, "first")
        with OpenedDirectory(second) as second_root:
            second_readiness = fsync_tree(second_root, parent, "second")
        with pytest.raises(PublicationAmbiguousError):
            exchange_exact(
                parent,
                "first",
                first_expected,
                parent,
                "second",
                second_expected,
                first_readiness=first_readiness,
                second_readiness=second_readiness,
                fault_hook=mutate,
            )
    assert first.is_dir() and second.is_dir()


def test_exchange_rejects_mixed_kinds_and_pre_mutation_replacement(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    first_expected = _write(first, b"first")
    second.mkdir(mode=0o700)
    with OpenedDirectory(tmp_path) as parent:
        with pytest.raises(PublicationPolicyError):
            exchange_exact(
                parent,
                "first",
                first_expected,
                parent,
                "second",
                _identity(second),
            )

    shutil.rmtree(second)
    second_expected = _write(second, b"second")

    def replace(point: str) -> None:
        if point == "exchange-before-mutation":
            second.unlink()
            _write(second, b"competitor")

    with OpenedDirectory(tmp_path) as parent:
        with pytest.raises(PublicationIdentityError):
            exchange_exact(
                parent,
                "first",
                first_expected,
                parent,
                "second",
                second_expected,
                fault_hook=replace,
            )
    assert first.read_bytes() == b"first"
    assert second.read_bytes() == b"competitor"


def test_exchange_post_mutation_failure_retains_both_swapped_names(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    first_expected = _write(first, b"first")
    second_expected = _write(second, b"second")
    with OpenedDirectory(tmp_path) as parent:
        with pytest.raises(PublicationAmbiguousError):
            exchange_exact(
                parent,
                "first",
                first_expected,
                parent,
                "second",
                second_expected,
                fault_hook=FaultHook(failure_at="exchange-after-mutation"),
            )
    assert first.read_bytes() == b"second"
    assert second.read_bytes() == b"first"


@pytest.mark.parametrize("checkpoint", (
    "exchange-before-final-validation",
    "exchange-after-final-validation",
))
@pytest.mark.parametrize("mutation", ("bytes", "size", "mode", "owner", "link"))
def test_exchange_rejects_same_inode_post_mutation_changes(
    checkpoint: str,
    mutation: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    first_expected = _write(first, b"first")
    second_expected = _write(second, b"second")
    changed = False
    owner_changed = False
    real_fstat = os.fstat

    def observe_owner(fd: int):
        result = real_fstat(fd)
        if owner_changed and result.st_ino == second_expected.ino:
            return _different_uid(result)
        return result

    monkeypatch.setattr(publication.os, "fstat", observe_owner)

    def mutate(point: str) -> None:
        nonlocal changed, owner_changed
        if point != checkpoint or changed:
            return
        changed = True
        if mutation == "bytes":
            first.write_bytes(b"SECOND")
        elif mutation == "size":
            with first.open("ab") as stream:
                stream.write(b"!")
        elif mutation == "mode":
            first.chmod(0o400)
        elif mutation == "owner":
            owner_changed = True
        else:
            os.link(first, tmp_path / "retained-link")

    with OpenedDirectory(tmp_path) as parent:
        with pytest.raises(PublicationAmbiguousError):
            exchange_exact(
                parent,
                "first",
                first_expected,
                parent,
                "second",
                second_expected,
                fault_hook=mutate,
            )
    assert first.stat().st_ino == second_expected.ino
    assert second.stat().st_ino == first_expected.ino


def test_exchange_parent_fsync_failure_retains_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    first_expected = _write(first, b"first")
    second_expected = _write(second, b"second")
    real_fsync = os.fsync

    def fail_directory(fd: int) -> None:
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError("failure")
        real_fsync(fd)

    monkeypatch.setattr(publication.os, "fsync", fail_directory)
    with OpenedDirectory(tmp_path) as parent:
        with pytest.raises(PublicationDurabilityError):
            exchange_exact(
                parent,
                "first",
                first_expected,
                parent,
                "second",
                second_expected,
            )
    assert first.read_bytes() == b"second"
    assert second.read_bytes() == b"first"


def test_exchange_cross_parent_fsyncs_files_then_parents_in_order(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_parent_path = tmp_path / "first-parent"
    second_parent_path = tmp_path / "second-parent"
    first_parent_path.mkdir()
    second_parent_path.mkdir()
    first_expected = _write(first_parent_path / "first", b"first")
    second_expected = _write(second_parent_path / "second", b"second")
    order: list[int] = []
    real_fsync = os.fsync

    def record(fd: int) -> None:
        order.append(os.fstat(fd).st_ino)
        real_fsync(fd)

    monkeypatch.setattr(publication.os, "fsync", record)
    with (
        OpenedDirectory(first_parent_path) as first_parent,
        OpenedDirectory(second_parent_path) as second_parent,
    ):
        first_parent_inode = first_parent.identity.ino
        second_parent_inode = second_parent.identity.ino
        exchange_exact(
            first_parent,
            "first",
            first_expected,
            second_parent,
            "second",
            second_expected,
        )
    assert order == [
        first_expected.ino,
        second_expected.ino,
        first_parent_inode,
        second_parent_inode,
    ]


def test_exchange_closes_first_pin_when_second_pin_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_path = tmp_path / "first-parent"
    second_path = tmp_path / "second-parent"
    first_path.mkdir()
    second_path.mkdir()
    first_expected = _write(first_path / "first", b"first")
    second_expected = _write(second_path / "second", b"second")
    pins = _fail_second_directory_pin(monkeypatch)
    with (
        OpenedDirectory(first_path) as first_parent,
        OpenedDirectory(second_path) as second_parent,
    ):
        with pytest.raises(RuntimeError, match="injected second pin failure"):
            exchange_exact(
                first_parent,
                "first",
                first_expected,
                second_parent,
                "second",
                second_expected,
            )
    assert len(pins) == 1
    with pytest.raises(PublicationIdentityError):
        pins[0].fileno()


def test_fsync_tree_orders_deepest_children_then_parents(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root_path = tmp_path / "tree"
    child_path = root_path / "child"
    root_path.mkdir(mode=0o700)
    child_path.mkdir(mode=0o700)
    file_path = child_path / "value"
    _write(file_path, b"value")
    expected_order = [
        file_path.stat().st_ino,
        child_path.stat().st_ino,
        root_path.stat().st_ino,
        tmp_path.stat().st_ino,
    ]
    order: list[int] = []
    real_fsync = os.fsync

    def record(fd: int) -> None:
        order.append(os.fstat(fd).st_ino)
        real_fsync(fd)

    monkeypatch.setattr(publication.os, "fsync", record)
    with OpenedDirectory(tmp_path) as parent, OpenedDirectory(root_path) as root:
        readiness = fsync_tree(root, parent, "tree")
        assert readiness.root_identity == root.identity
    assert order == expected_order


def test_fsync_tree_accepts_an_already_opened_regular_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "value"
    _write(path, b"value")
    order: list[int] = []
    real_fsync = os.fsync

    def record(fd: int) -> None:
        order.append(os.fstat(fd).st_ino)
        real_fsync(fd)

    monkeypatch.setattr(publication.os, "fsync", record)
    with OpenedDirectory(tmp_path) as parent, OpenedFile(path) as root:
        fsync_tree(root, parent, "value")
    assert order == [path.stat().st_ino, tmp_path.stat().st_ino]


def test_fsync_tree_closes_root_pin_when_parent_pin_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root_path = tmp_path / "root"
    parent_path = tmp_path / "parent"
    root_path.mkdir()
    parent_path.mkdir()
    pins = _fail_second_directory_pin(monkeypatch)
    with (
        OpenedDirectory(root_path) as root,
        OpenedDirectory(parent_path) as parent,
    ):
        with pytest.raises(RuntimeError, match="injected second pin failure"):
            fsync_tree(root, parent, "root")
    assert len(pins) == 1
    with pytest.raises(PublicationIdentityError):
        pins[0].fileno()


@pytest.mark.parametrize("operation", ("publish", "exchange", "tree"))
def test_same_opened_parent_pin_is_closed_once(
    operation: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_expected = _write(tmp_path / "first", b"first")
    second_expected = _write(tmp_path / "second", b"second")
    closed: list[int] = []
    real_close = publication._PinnedObject.close

    def record_close(pin: publication._PinnedObject) -> None:
        closed.append(id(pin))
        real_close(pin)

    monkeypatch.setattr(publication._PinnedObject, "close", record_close)
    with OpenedDirectory(tmp_path) as parent:
        if operation == "publish":
            publish_no_clobber(
                parent,
                "first",
                first_expected,
                parent,
                "destination",
            )
        elif operation == "exchange":
            exchange_exact(
                parent,
                "first",
                first_expected,
                parent,
                "second",
                second_expected,
            )
        else:
            with pytest.raises(PublicationTreeError):
                fsync_tree(parent, parent, "first")
    assert len(closed) == len(set(closed)) == 1


def test_fsync_tree_rejects_wrong_publication_parent(tmp_path: Path) -> None:
    root_path = tmp_path / "tree"
    wrong_path = tmp_path / "wrong"
    root_path.mkdir(mode=0o700)
    wrong_path.mkdir(mode=0o700)
    (wrong_path / "tree").mkdir(mode=0o700)
    with OpenedDirectory(wrong_path) as wrong, OpenedDirectory(root_path) as root:
        with pytest.raises(PublicationTreeError):
            fsync_tree(root, wrong, "tree")


def test_tree_readiness_is_immutable_and_parent_name_bound(tmp_path: Path) -> None:
    root_path = tmp_path / "tree"
    root_path.mkdir(mode=0o700)
    with OpenedDirectory(tmp_path) as parent, OpenedDirectory(root_path) as root:
        readiness = fsync_tree(root, parent, "tree")
    assert isinstance(readiness, TreeReadiness)
    assert readiness.root_name == "tree"
    assert "digest" not in repr(readiness)
    with pytest.raises(TypeError):
        TreeReadiness()
    with pytest.raises(FrozenInstanceError):
        readiness.root_name = "other"  # type: ignore[misc]


def test_fsync_tree_restats_child_name_after_recursive_descriptor_validation(
    tmp_path: Path,
) -> None:
    root_path = tmp_path / "tree"
    root_path.mkdir(mode=0o700)
    value = root_path / "value"
    retained = root_path / "retained"
    _write(value, b"original")
    changed = False

    def replace(point: str) -> None:
        nonlocal changed
        if point == "tree-before-child-final-name-check" and not changed:
            changed = True
            value.rename(retained)
            _write(value, b"replacement")

    with OpenedDirectory(tmp_path) as parent, OpenedDirectory(root_path) as root:
        with pytest.raises(PublicationTreeError):
            fsync_tree(root, parent, "tree", fault_hook=replace)
    assert retained.read_bytes() == b"original"
    assert value.read_bytes() == b"replacement"


@pytest.mark.parametrize("kind", ("symlink", "hardlink", "fifo"))
def test_fsync_tree_rejects_links_and_unsupported_types(
    kind: str,
    tmp_path: Path,
) -> None:
    root_path = tmp_path / "tree"
    root_path.mkdir(mode=0o700)
    target = root_path / "target"
    _write(target, b"target")
    if kind == "symlink":
        (root_path / "bad").symlink_to(target)
    elif kind == "hardlink":
        os.link(target, root_path / "bad")
    else:
        os.mkfifo(root_path / "bad")
    with OpenedDirectory(tmp_path) as parent, OpenedDirectory(root_path) as root:
        with pytest.raises(PublicationTreeError):
            fsync_tree(root, parent, "tree")


def test_fsync_tree_rejects_final_validation_replacement(tmp_path: Path) -> None:
    root_path = tmp_path / "tree"
    root_path.mkdir(mode=0o700)
    value = root_path / "value"
    _write(value, b"original")

    def replace(point: str) -> None:
        if point == "tree-before-final-validation":
            value.unlink()
            _write(value, b"replacement")

    with OpenedDirectory(tmp_path) as parent, OpenedDirectory(root_path) as root:
        with pytest.raises(PublicationTreeError):
            fsync_tree(root, parent, "tree", fault_hook=replace)
    assert value.read_bytes() == b"replacement"


def test_fsync_tree_rechecks_after_terminal_checkpoint(tmp_path: Path) -> None:
    root_path = tmp_path / "tree"
    root_path.mkdir(mode=0o700)
    value = root_path / "value"
    _write(value, b"original")

    def replace(point: str) -> None:
        if point == "tree-after-final-validation":
            value.unlink()
            _write(value, b"replacement")

    with OpenedDirectory(tmp_path) as parent, OpenedDirectory(root_path) as root:
        with pytest.raises(PublicationTreeError):
            fsync_tree(root, parent, "tree", fault_hook=replace)
    assert value.read_bytes() == b"replacement"


def test_cross_device_publication_is_rejected_where_available(tmp_path: Path) -> None:
    shared = Path("/dev/shm")
    if not shared.is_dir() or shared.stat().st_dev == tmp_path.stat().st_dev:
        pytest.skip("a writable second filesystem is unavailable")
    destination_path = Path(tempfile.mkdtemp(prefix="platform-pki-publication-", dir=shared))
    try:
        source = tmp_path / "source"
        expected = _write(source, b"source")
        with (
            OpenedDirectory(tmp_path) as source_parent,
            OpenedDirectory(destination_path) as destination_parent,
        ):
            with pytest.raises(PublicationCrossDeviceError):
                publish_no_clobber(
                    source_parent,
                    "source",
                    expected,
                    destination_parent,
                    "destination",
                )
        assert source.read_bytes() == b"source"
    finally:
        destination_path.rmdir()


def test_cross_device_exchange_is_rejected_where_available(tmp_path: Path) -> None:
    shared = Path("/dev/shm")
    if not shared.is_dir() or shared.stat().st_dev == tmp_path.stat().st_dev:
        pytest.skip("a writable second filesystem is unavailable")
    second_parent_path = Path(
        tempfile.mkdtemp(prefix="platform-pki-exchange-", dir=shared)
    )
    try:
        first_expected = _write(tmp_path / "first", b"first")
        second_expected = _write(second_parent_path / "second", b"second")
        with (
            OpenedDirectory(tmp_path) as first_parent,
            OpenedDirectory(second_parent_path) as second_parent,
        ):
            with pytest.raises(PublicationCrossDeviceError):
                exchange_exact(
                    first_parent,
                    "first",
                    first_expected,
                    second_parent,
                    "second",
                    second_expected,
                )
        assert (tmp_path / "first").read_bytes() == b"first"
        assert (second_parent_path / "second").read_bytes() == b"second"
    finally:
        shutil.rmtree(second_parent_path)


def test_cross_device_replacement_is_rejected_where_available(tmp_path: Path) -> None:
    shared = Path("/dev/shm")
    if not shared.is_dir() or shared.stat().st_dev == tmp_path.stat().st_dev:
        pytest.skip("a writable second filesystem is unavailable")
    destination_parent_path = Path(
        tempfile.mkdtemp(prefix="platform-pki-replacement-", dir=shared)
    )
    try:
        source_expected = _write(tmp_path / "source", b"new")
        destination = destination_parent_path / "destination"
        destination_expected = _write(destination, b"old")
        with (
            OpenedDirectory(tmp_path) as source_parent,
            OpenedDirectory(destination_parent_path) as destination_parent,
        ):
            with pytest.raises(PublicationCrossDeviceError):
                replace_exact(
                    source_parent,
                    "source",
                    source_expected,
                    destination_parent,
                    "destination",
                    destination_expected,
                )
        assert (tmp_path / "source").read_bytes() == b"new"
        assert destination.read_bytes() == b"old"
    finally:
        shutil.rmtree(destination_parent_path)


@pytest.mark.parametrize("_iteration", range(20))
def test_simultaneous_exact_replacements_preserve_only_enumerated_states(
    _iteration: int,
    tmp_path: Path,
) -> None:
    del _iteration
    destination = tmp_path / "destination"
    original_identities = {b"old": _write(destination, b"old")}
    for name, payload in (("source-first", b"first"), ("source-second", b"second")):
        original_identities[payload] = _write(tmp_path / name, payload)
    script = (
        "import os,sys\n"
        "from src.platform_pki.filesystem import OpenedDirectory,identity_at\n"
        "from src.platform_pki.publication import replace_exact,"
        "PublicationAmbiguousError,PublicationIdentityError\n"
        "ready=int(sys.argv[3]); release=int(sys.argv[4])\n"
        "def pause(point):\n"
        " if point != 'replacement-before-exchange': return\n"
        " os.write(ready,b'R'); os.close(ready)\n"
        " try:\n"
        "  if os.read(release,1) != b'G': raise RuntimeError('release closed')\n"
        " finally: os.close(release)\n"
        "with OpenedDirectory(sys.argv[1]) as parent:\n"
        " source=identity_at(sys.argv[2],dir_fd=parent)\n"
        " destination=identity_at('destination',dir_fd=parent)\n"
        " try: replace_exact(parent,sys.argv[2],source,parent,'destination',"
        "destination,pause_hook=pause)\n"
        " except PublicationIdentityError: print('identity')\n"
        " except PublicationAmbiguousError: print('ambiguous')\n"
        " else: print('replaced')\n"
    )
    processes: list[subprocess.Popen[bytes]] = []
    ready_reads: list[int] = []
    release_writes: list[int] = []
    open_fds: set[int] = set()
    try:
        for name in ("source-first", "source-second"):
            ready_read, ready_write = os.pipe()
            release_read, release_write = os.pipe()
            open_fds.update((ready_read, ready_write, release_read, release_write))
            try:
                process = subprocess.Popen(
                    (
                        PYTHON,
                        "-c",
                        script,
                        os.fspath(tmp_path),
                        name,
                        str(ready_write),
                        str(release_read),
                    ),
                    cwd=ROOT,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    pass_fds=(ready_write, release_read),
                )
            finally:
                os.close(ready_write)
                os.close(release_read)
                open_fds.difference_update((ready_write, release_read))
            processes.append(process)
            ready_reads.append(ready_read)
            release_writes.append(release_write)
        for descriptor in ready_reads:
            readable, _, _ = select.select((descriptor,), (), (), 3)
            assert readable and os.read(descriptor, 1) == b"R"
            os.close(descriptor)
            open_fds.discard(descriptor)
        for descriptor in release_writes:
            os.write(descriptor, b"G")
            os.close(descriptor)
            open_fds.discard(descriptor)
        observations = [
            (*process.communicate(timeout=3), process.returncode)
            for process in processes
        ]
    finally:
        for descriptor in open_fds:
            try:
                os.close(descriptor)
            except OSError:
                pass
        for process in processes:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=3)
    assert all(returncode == 0 for _stdout, _stderr, returncode in observations)
    assert all(stderr == b"" for _stdout, stderr, _returncode in observations)
    outcomes = tuple(
        stdout.removesuffix(b"\n").decode("ascii")
        for stdout, _stderr, _returncode in observations
    )
    assert outcomes in {
        ("replaced", "identity"),
        ("identity", "replaced"),
        ("replaced", "ambiguous"),
        ("ambiguous", "replaced"),
        ("ambiguous", "ambiguous"),
    }

    names = {
        "destination": destination,
        "source-first": tmp_path / "source-first",
        "source-second": tmp_path / "source-second",
    }
    located: dict[int, str] = {}
    for name, path in names.items():
        if not path.exists():
            continue
        payload = path.read_bytes()
        assert payload in original_identities
        identity = _identity(path)
        assert identity.state == original_identities[payload].state
        assert identity.mtime_ns == original_identities[payload].mtime_ns
        assert identity.ino not in located
        located[identity.ino] = name

    for payload in (b"first", b"second"):
        assert original_identities[payload].ino in located
    assert destination.read_bytes() in {b"first", b"second"}
    old_retained = original_identities[b"old"].ino in located
    absent_sources = sum(
        not names[name].exists() for name in ("source-first", "source-second")
    )
    if old_retained:
        assert outcomes == ("ambiguous", "ambiguous")
        assert located[original_identities[b"old"].ino] in {
            "source-first",
            "source-second",
        }
        assert absent_sources == 0
    else:
        assert absent_sources == 1
        absent_index = next(
            index
            for index, name in enumerate(("source-first", "source-second"))
            if not names[name].exists()
        )
        assert outcomes[absent_index] in {"replaced", "ambiguous"}


def test_simultaneous_no_clobber_publishers_have_one_winner(tmp_path: Path) -> None:
    script = (
        "import os,sys\n"
        "from src.platform_pki.filesystem import OpenedDirectory\n"
        "from src.platform_pki.publication import "
        "atomic_write_bytes,PublicationDestinationExistsError\n"
        "ready=int(sys.argv[2]); release=int(sys.argv[3])\n"
        "def pause(point):\n"
        " if point != 'publication-before-mutation': return\n"
        " os.write(ready,b'R'); os.close(ready)\n"
        " try:\n"
        "  if os.read(release,1) != b'G': raise RuntimeError('release pipe closed')\n"
        " finally: os.close(release)\n"
        "with OpenedDirectory(sys.argv[1]) as parent:\n"
        " try: atomic_write_bytes(parent,'destination',sys.argv[4].encode(),"
        "pause_hook=pause)\n"
        " except PublicationDestinationExistsError: print('exists')\n"
        " else: print('published')\n"
    )
    processes: list[tuple[bytes, subprocess.Popen[bytes]]] = []
    ready_fds: dict[int, int] = {}
    release_fds: list[int] = []
    open_parent_fds: set[int] = set()
    try:
        for index, payload in enumerate((b"first", b"second")):
            ready_read, ready_write = os.pipe()
            release_read, release_write = os.pipe()
            open_parent_fds.update((ready_read, ready_write, release_read, release_write))
            try:
                process = subprocess.Popen(
                    (
                        PYTHON,
                        "-c",
                        script,
                        os.fspath(tmp_path),
                        str(ready_write),
                        str(release_read),
                        payload.decode(),
                    ),
                    cwd=ROOT,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    pass_fds=(ready_write, release_read),
                )
            finally:
                os.close(ready_write)
                os.close(release_read)
                open_parent_fds.difference_update((ready_write, release_read))
            processes.append((payload, process))
            ready_fds[ready_read] = index
            release_fds.append(release_write)

        deadline = time.monotonic() + 3
        while ready_fds:
            remaining = deadline - time.monotonic()
            readable, _, _ = select.select(tuple(ready_fds), (), (), max(0, remaining))
            if not readable:
                for index in ready_fds.values():
                    process = processes[index][1]
                    if process.poll() is not None:
                        stdout, stderr = process.communicate(timeout=1)
                        pytest.fail(
                            f"publisher {index} exited before readiness: "
                            f"return code {process.returncode}, stderr={stderr!r}, "
                            f"stdout={stdout!r}"
                        )
                pytest.fail("publishers did not become ready before timeout")
            for descriptor in readable:
                index = ready_fds.pop(descriptor)
                signal_byte = os.read(descriptor, 1)
                os.close(descriptor)
                open_parent_fds.discard(descriptor)
                if signal_byte != b"R":
                    process = processes[index][1]
                    process.wait(timeout=1)
                    stdout, stderr = process.communicate()
                    pytest.fail(
                        f"publisher {index} exited before readiness: "
                        f"return code {process.returncode}, stderr={stderr!r}, "
                        f"stdout={stdout!r}"
                    )

        for descriptor in release_fds:
            os.write(descriptor, b"G")
            os.close(descriptor)
            open_parent_fds.discard(descriptor)
        observations = [
            (payload, *process.communicate(timeout=3), process.returncode)
            for payload, process in processes
        ]
    finally:
        for descriptor in open_parent_fds:
            try:
                os.close(descriptor)
            except OSError:
                pass
        for _payload, process in processes:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=3)
    assert all(returncode == 0 for _payload, _stdout, _stderr, returncode in observations)
    assert all(stderr == b"" for _payload, _stdout, stderr, _returncode in observations)
    winners = [
        payload
        for payload, stdout, _stderr, _returncode in observations
        if stdout == b"published\n"
    ]
    losers = [
        payload
        for payload, stdout, _stderr, _returncode in observations
        if stdout == b"exists\n"
    ]
    assert len(winners) == len(losers) == 1
    assert (tmp_path / "destination").read_bytes() == winners[0]
    assert not tuple(tmp_path.glob(".destination.stage-*"))


@pytest.mark.parametrize(
    ("checkpoint", "published"),
    (
        ("publication-before-mutation", False),
        ("publication-after-mutation", True),
    ),
)
def test_sigkill_at_publication_mutation_boundaries_retains_observable_state(
    checkpoint: str,
    published: bool,
    tmp_path: Path,
) -> None:
    script = (
        "from src.platform_pki.faults import FaultHook; "
        "from src.platform_pki.filesystem import OpenedDirectory; "
        "from src.platform_pki.publication import stage_file_bytes,publish_no_clobber; "
        "import sys; "
        "p=OpenedDirectory(sys.argv[1]); s=stage_file_bytes(p,'destination',b'payload'); "
        "publish_no_clobber(p,s.name,s.identity,p,'destination',"
        "fault_hook=FaultHook(crash_at=sys.argv[2]))"
    )
    result = subprocess.run(
        (PYTHON, "-c", script, os.fspath(tmp_path), checkpoint),
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=3,
    )
    assert shell_status(result.returncode) == 137
    assert result.stdout == result.stderr == b""
    destination = tmp_path / "destination"
    assert destination.exists() is published
    stages = tuple(tmp_path.glob(".destination.stage-*"))
    if published:
        assert destination.read_bytes() == b"payload"
        assert not stages
    else:
        assert len(stages) == 1
        assert stages[0].read_bytes() == b"payload"


@pytest.mark.parametrize(
    ("checkpoint", "source_retained"),
    (
        ("replacement-after-exchange", True),
        ("replacement-after-exchange-durability", True),
        ("replacement-before-old-disposition", True),
        ("replacement-after-old-disposition", False),
        ("replacement-terminal-validation", False),
    ),
)
def test_sigkill_after_replacement_exchange_preserves_recovery_observations(
    checkpoint: str,
    source_retained: bool,
    tmp_path: Path,
) -> None:
    _write(tmp_path / "source", b"new")
    _write(tmp_path / "destination", b"old")
    script = (
        "import sys\n"
        "from src.platform_pki.faults import FaultHook\n"
        "from src.platform_pki.filesystem import OpenedDirectory,identity_at\n"
        "from src.platform_pki.publication import replace_exact\n"
        "with OpenedDirectory(sys.argv[1]) as parent:\n"
        " source=identity_at('source',dir_fd=parent)\n"
        " destination=identity_at('destination',dir_fd=parent)\n"
        " replace_exact(parent,'source',source,parent,'destination',destination,"
        "fault_hook=FaultHook(crash_at=sys.argv[2]))\n"
    )
    result = subprocess.run(
        (PYTHON, "-c", script, os.fspath(tmp_path), checkpoint),
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=3,
    )
    assert shell_status(result.returncode) == 137
    assert result.stdout == result.stderr == b""
    assert (tmp_path / "destination").read_bytes() == b"new"
    assert (tmp_path / "source").exists() is source_retained
    if source_retained:
        assert (tmp_path / "source").read_bytes() == b"old"


@pytest.mark.parametrize(
    "checkpoint",
    (
        "replacement-after-exchange",
        "replacement-after-exchange-durability",
        "replacement-before-old-disposition",
        "replacement-after-old-disposition",
        "replacement-terminal-validation",
    ),
)
def test_sigkill_after_directory_exchange_retains_both_exact_complete_trees(
    checkpoint: str,
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir(mode=0o700)
    destination.mkdir(mode=0o700)
    _write(source / "value", b"new")
    _write(destination / "value", b"old")
    with OpenedDirectory(tmp_path) as parent:
        source_readiness = _tree_readiness(parent, source, "source")
        destination_readiness = _tree_readiness(
            parent, destination, "destination"
        )
    script = (
        "import sys\n"
        "from src.platform_pki.faults import FaultHook\n"
        "from src.platform_pki.filesystem import OpenedDirectory,identity_at\n"
        "from src.platform_pki.publication import fsync_tree,replace_exact\n"
        "with OpenedDirectory(sys.argv[1]) as parent:\n"
        " source=identity_at('source',dir_fd=parent)\n"
        " destination=identity_at('destination',dir_fd=parent)\n"
        " with OpenedDirectory(sys.argv[1]+'/source') as root:\n"
        "  source_ready=fsync_tree(root,parent,'source')\n"
        " with OpenedDirectory(sys.argv[1]+'/destination') as root:\n"
        "  destination_ready=fsync_tree(root,parent,'destination')\n"
        " replace_exact(parent,'source',source,parent,'destination',destination,"
        "source_readiness=source_ready,destination_readiness=destination_ready,"
        "fault_hook=FaultHook(crash_at=sys.argv[2]))\n"
    )
    result = subprocess.run(
        (PYTHON, "-c", script, os.fspath(tmp_path), checkpoint),
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=3,
    )
    assert shell_status(result.returncode) == 137
    assert result.stdout == result.stderr == b""
    with OpenedDirectory(tmp_path) as parent:
        retained_old = _tree_readiness(parent, source, "source")
        retained_new = _tree_readiness(parent, destination, "destination")
    _assert_same_tree(retained_old, destination_readiness)
    _assert_same_tree(retained_new, source_readiness)


def test_owned_descriptor_is_closed_across_exec_even_with_close_fds_false(
    tmp_path: Path,
) -> None:
    with OpenedDirectory(tmp_path) as parent:
        stage = stage_file_bytes(parent, "destination", b"payload")
        try:
            descriptor = stage.fileno()
            result = subprocess.run(
                (
                    PYTHON,
                    "-c",
                    "import os,sys;\ntry: os.fstat(int(sys.argv[1]))\n"
                    "except OSError: print('closed')\nelse: print('inherited')",
                    str(descriptor),
                ),
                close_fds=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            )
        finally:
            stage.cleanup()
            stage.close()
    assert result.stdout == b"closed\n"
    assert result.stderr == b""


def test_public_errors_are_static_and_redact_paths_bytes_and_os_errors(tmp_path: Path) -> None:
    secret_path = tmp_path / "secret-name"
    secret_data = b"secret-payload"
    _write(secret_path, secret_data)
    with OpenedDirectory(tmp_path) as parent:
        with pytest.raises(PublicationDestinationExistsError) as caught:
            atomic_write_bytes(parent, "secret-name", secret_data)
    error = caught.value
    assert isinstance(error, ApplicationError)
    rendered = render_error(error)
    for secret in ("secret-name", "secret-payload", os.fspath(tmp_path)):
        assert secret not in str(error)
        assert secret not in repr(error)
        assert secret not in rendered
    assert "Traceback" not in rendered
    assert issubclass(PublicationAmbiguousError, PublicationError)
    assert issubclass(PublicationDurabilityError, PublicationAmbiguousError)
    assert issubclass(PublicationCleanupError, PublicationError)
    assert issubclass(
        PublicationReplacementAmbiguousError,
        PublicationAmbiguousError,
    )
    assert issubclass(
        PublicationReplacementCleanupError,
        PublicationReplacementAmbiguousError,
    )
