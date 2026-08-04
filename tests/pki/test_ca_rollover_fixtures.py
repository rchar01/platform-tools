import stat
from collections.abc import Callable
from pathlib import Path

import pytest

from .conftest import RolloverWorkspace


pytestmark = pytest.mark.pki


def test_generation_case_copy_preserves_isolated_public_state(
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    public_state_snapshot: Callable[[RolloverWorkspace], tuple[str, ...]],
) -> None:
    first = rollover_case_factory("metadata-copy-one")
    second = rollover_case_factory("metadata-copy-two")
    default_namespace = Path.home() / ".config/platform-infrastructure"

    assert first.root != second.root
    assert not first.root.is_relative_to(default_namespace)
    assert not second.root.is_relative_to(default_namespace)
    assert stat.S_IMODE(first.passphrase_file.stat().st_mode) == 0o600
    assert stat.S_IMODE(
        (first.pki / "inventory/services.yml").stat().st_mode
    ) == 0o600
    assert stat.S_IMODE(
        (first.private_repo / "pki/services.yml").stat().st_mode
    ) == 0o600
    assert (first.pki / "state/active-issuer").read_text() == (
        "root=g1\nintermediate=g1-i1\n"
    )
    snapshot = public_state_snapshot(first)
    assert snapshot == public_state_snapshot(second)
    assert snapshot
    assert all(entry.startswith("state/") for entry in snapshot)

    for relative in (
        "authorities/roots/g1/private/root-ca.key",
        "authorities/intermediates/g1-i1/private/intermediate-ca.key",
    ):
        first_metadata = (first.pki / relative).stat()
        second_metadata = (second.pki / relative).stat()
        assert stat.S_IMODE(first_metadata.st_mode) == 0o600
        assert stat.S_IMODE(second_metadata.st_mode) == 0o600
        assert first_metadata.st_size == second_metadata.st_size
        assert first_metadata.st_mtime_ns == second_metadata.st_mtime_ns
        assert first_metadata.st_ino != second_metadata.st_ino


@pytest.mark.parametrize(
    "name", ["", "..", "../escape", "/tmp/escape", "a/b"]
)
def test_rollover_factories_reject_unsafe_names(
    rollover_workspace_factory: Callable[[str], RolloverWorkspace],
    name: str,
) -> None:
    with pytest.raises(ValueError, match="one relative path component"):
        rollover_workspace_factory(name)


def test_public_state_snapshot_rejects_unlisted_file_without_reading_it(
    rollover_case_factory: Callable[[str], RolloverWorkspace],
    public_state_snapshot: Callable[[RolloverWorkspace], tuple[str, ...]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = rollover_case_factory("unexpected-state")
    unexpected = case.pki / "state/0-private.key"
    unexpected.write_text("must-not-be-read\n")
    unexpected.chmod(0o600)
    original_read_bytes = Path.read_bytes

    def guarded_read_bytes(path: Path) -> bytes:
        assert path != unexpected, "snapshot read an unlisted state file"
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", guarded_read_bytes)

    with pytest.raises(ValueError, match="state snapshot path is not public"):
        public_state_snapshot(case)
