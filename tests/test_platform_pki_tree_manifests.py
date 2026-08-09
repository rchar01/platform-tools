from __future__ import annotations

import hashlib
import os
from dataclasses import replace
from pathlib import Path

import pytest

from src.platform_pki import publication
from src.platform_pki.filesystem import (
    FileIdentity,
    FilesystemIdentityError,
    FilesystemReadLimitError,
    OpenedDirectory,
    OpenedFile,
    identity_at,
)
from src.platform_pki.persisted_identity import (
    serialize_directory_identity,
    serialize_file_identity,
    serialize_file_object_state,
)
from src.platform_pki.publication import (
    PublicationTreeError,
    TreeReadiness,
    remove_exact_tree,
)
from src.platform_pki.tree_manifests import (
    TreeManifestError,
    remove_manifested_tree,
    validate_provenance_manifest,
    validate_tree_manifest,
)


def _identity(path: Path) -> FileIdentity:
    identity = identity_at(path)
    assert isinstance(identity, FileIdentity)
    return identity


def _secret(relative: str, provenance: bool) -> bool:
    if provenance:
        return relative.startswith("quarantine/")
    parts = relative.split("/")
    return (
        "private" in parts[:-1]
        or relative.endswith(".key")
        or "passphrase" in relative
    )


def _manifest_bytes(
    root: Path,
    *,
    excluded: str,
    provenance: bool = False,
) -> bytes:
    rows = []
    paths = sorted(
        (
            path
            for path in root.rglob("*")
            if path.relative_to(root).as_posix() != excluded
        ),
        key=lambda path: os.fsencode(path.relative_to(root).as_posix()),
    )
    for path in paths:
        relative = path.relative_to(root).as_posix()
        identity = _identity(path)
        if identity.kind == "directory":
            kind = "directory"
            persisted = serialize_directory_identity(identity.directory)
            digest = "-"
        else:
            kind = "regular empty file" if identity.size == 0 else "regular file"
            persisted = serialize_file_identity(identity)
            digest = (
                "secret"
                if _secret(relative, provenance)
                else hashlib.sha256(path.read_bytes()).hexdigest()
            )
        rows.append(f"{kind}|{relative}|{persisted}|{digest}\n".encode())
    return b"".join(rows)


def _write_manifest(
    root: Path,
    name: str,
    *,
    provenance: bool = False,
) -> tuple[Path, FileIdentity, str]:
    manifest = root / name
    manifest.write_bytes(
        _manifest_bytes(root, excluded=name, provenance=provenance)
    )
    manifest.chmod(0o600)
    identity = _identity(manifest)
    return manifest, identity, hashlib.sha256(manifest.read_bytes()).hexdigest()


def _tree(tmp_path: Path) -> tuple[Path, Path]:
    parent = tmp_path / "parent"
    root = parent / "tree"
    (root / "private").mkdir(mode=0o700, parents=True)
    parent.chmod(0o700)
    root.chmod(0o700)
    (root / "public").mkdir(mode=0o700)
    (root / "private/ca.key").write_bytes(b"private key bytes\n")
    (root / "private/ca.key").chmod(0o600)
    (root / "public/certificate.pem").write_bytes(b"public certificate\n")
    (root / "public/certificate.pem").chmod(0o600)
    return parent, root


def test_tree_manifest_returns_remove_exact_tree_readiness(tmp_path: Path) -> None:
    parent_path, root_path = _tree(tmp_path)
    manifest_path, manifest_identity, digest = _write_manifest(
        root_path, "tree.manifest"
    )
    root_identity: FileIdentity | None = None
    readiness: TreeReadiness | None = None
    with (
        OpenedDirectory(parent_path) as parent,
        OpenedDirectory(root_path) as root,
        OpenedFile(manifest_path) as manifest,
    ):
        root_identity = root.identity
        readiness = validate_tree_manifest(
            root,
            parent,
            "tree",
            manifest,
            serialize_file_identity(manifest_identity),
            digest,
            "tree.manifest",
        )
        assert isinstance(readiness, TreeReadiness)
    assert root_identity is not None and readiness is not None
    with OpenedDirectory(parent_path) as parent:
        remove_exact_tree(parent, "tree", root_identity, readiness)
    assert not root_path.exists()


def test_remove_manifested_tree_binds_root_and_excluded_manifest(tmp_path: Path) -> None:
    parent_path, root_path = _tree(tmp_path)
    manifest_path, manifest_identity, digest = _write_manifest(
        root_path, "tree.manifest"
    )
    root_identity = _identity(root_path)
    with OpenedDirectory(parent_path) as parent, OpenedFile(manifest_path) as manifest:
        remove_manifested_tree(
            parent,
            "tree",
            serialize_directory_identity(root_identity.directory),
            manifest,
            manifest_identity,
            digest,
            "tree.manifest",
        )
    assert not root_path.exists()


def test_excluded_manifest_must_be_the_opened_in_tree_object(tmp_path: Path) -> None:
    parent_path, root_path = _tree(tmp_path)
    manifest_path, _manifest_identity, digest = _write_manifest(
        root_path, "tree.manifest"
    )
    external = tmp_path / "external.manifest"
    external.write_bytes(manifest_path.read_bytes())
    external.chmod(0o600)
    external_identity = _identity(external)
    with (
        OpenedDirectory(parent_path) as parent,
        OpenedDirectory(root_path) as root,
        OpenedFile(external) as manifest,
        pytest.raises(FilesystemIdentityError),
    ):
        validate_tree_manifest(
            root,
            parent,
            "tree",
            manifest,
            external_identity,
            digest,
            "tree.manifest",
        )


def test_manifest_accepts_persisted_object_state_expectation(tmp_path: Path) -> None:
    parent_path, root_path = _tree(tmp_path)
    manifest_path, manifest_identity, digest = _write_manifest(
        root_path, "tree.manifest"
    )
    readiness: TreeReadiness | None = None
    with (
        OpenedDirectory(parent_path) as parent,
        OpenedDirectory(root_path) as root,
        OpenedFile(manifest_path) as manifest,
    ):
        readiness = validate_tree_manifest(
            root,
            parent,
            "tree",
            manifest,
            serialize_file_object_state(manifest_identity.state),
            digest,
            "tree.manifest",
        )
    assert isinstance(readiness, TreeReadiness)


def test_provenance_uses_only_quarantine_literal_secret_policy(
    tmp_path: Path,
) -> None:
    parent = tmp_path / "parent"
    root = parent / "provenance"
    (root / "quarantine").mkdir(mode=0o700, parents=True)
    parent.chmod(0o700)
    root.chmod(0o700)
    (root / "private").mkdir(mode=0o700)
    (root / "quarantine/pki.env").write_bytes(b"secret\n")
    (root / "quarantine/pki.env").chmod(0o600)
    (root / "private/not-redacted").write_bytes(b"publicly hashed\n")
    (root / "private/not-redacted").chmod(0o600)
    manifest_path, manifest_identity, digest = _write_manifest(
        root, "provenance-manifest", provenance=True
    )
    rows = manifest_path.read_text().splitlines()
    assert next(row for row in rows if "quarantine/pki.env" in row).endswith("|secret")
    assert not next(row for row in rows if "private/not-redacted" in row).endswith(
        "|secret"
    )

    with (
        OpenedDirectory(parent) as opened_parent,
        OpenedDirectory(root) as opened_root,
        OpenedFile(manifest_path) as manifest,
    ):
        assert isinstance(
            validate_provenance_manifest(
                opened_root,
                opened_parent,
                "provenance",
                manifest,
                manifest_identity,
                digest,
            ),
            TreeReadiness,
        )


@pytest.mark.parametrize(
    "mutation",
    (
        lambda lines: lines[:-1],
        lambda lines: [*lines, lines[-1]],
        lambda lines: [lines[-1], *lines[:-1]],
        lambda lines: [lines[0].replace(b"|private|", b"|../private|"), *lines[1:]],
    ),
    ids=("incomplete", "duplicate", "order", "traversal"),
)
def test_manifest_rejects_incomplete_duplicate_unordered_and_traversal_rows(
    tmp_path: Path, mutation
) -> None:
    parent_path, root_path = _tree(tmp_path)
    manifest_path, _identity_before, _digest_before = _write_manifest(
        root_path, "tree.manifest"
    )
    lines = manifest_path.read_bytes().splitlines()
    manifest_path.write_bytes(b"\n".join(mutation(lines)) + b"\n")
    manifest_identity = _identity(manifest_path)
    digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    with (
        OpenedDirectory(parent_path) as parent,
        OpenedDirectory(root_path) as root,
        OpenedFile(manifest_path) as manifest,
        pytest.raises(TreeManifestError),
    ):
        validate_tree_manifest(
            root,
            parent,
            "tree",
            manifest,
            manifest_identity,
            digest,
            "tree.manifest",
        )


def test_manifest_enforces_secret_and_public_digest_literals(tmp_path: Path) -> None:
    parent_path, root_path = _tree(tmp_path)
    manifest_path, _manifest_identity, _digest = _write_manifest(
        root_path, "tree.manifest"
    )
    original = manifest_path.read_bytes()
    cases = (
        original.replace(b"|secret\n", b"|" + b"0" * 64 + b"\n", 1),
        original.replace(
            hashlib.sha256(b"public certificate\n").hexdigest().encode(),
            b"secret",
            1,
        ),
    )
    for data in cases:
        manifest_path.write_bytes(data)
        manifest_identity = _identity(manifest_path)
        digest = hashlib.sha256(data).hexdigest()
        with (
            OpenedDirectory(parent_path) as parent,
            OpenedDirectory(root_path) as root,
            OpenedFile(manifest_path) as manifest,
            pytest.raises(TreeManifestError),
        ):
            validate_tree_manifest(
                root,
                parent,
                "tree",
                manifest,
                manifest_identity,
                digest,
                "tree.manifest",
            )


@pytest.mark.parametrize("object_type", (b"directory", b"regular file"))
def test_manifest_normalizes_malformed_persisted_identity(
    tmp_path: Path, object_type: bytes
) -> None:
    parent_path, root_path = _tree(tmp_path)
    manifest_path, _manifest_identity, _digest = _write_manifest(
        root_path, "tree.manifest"
    )
    lines = manifest_path.read_bytes().splitlines()
    index = next(i for i, line in enumerate(lines) if line.startswith(object_type + b"|"))
    fields = lines[index].split(b"|")
    fields[2] = b"invalid"
    lines[index] = b"|".join(fields)
    manifest_path.write_bytes(b"\n".join(lines) + b"\n")
    manifest_identity = _identity(manifest_path)
    digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    with (
        OpenedDirectory(parent_path) as parent,
        OpenedDirectory(root_path) as root,
        OpenedFile(manifest_path) as manifest,
        pytest.raises(TreeManifestError, match="identity is invalid"),
    ):
        validate_tree_manifest(
            root,
            parent,
            "tree",
            manifest,
            manifest_identity,
            digest,
            "tree.manifest",
        )


def test_literal_secret_entry_still_requires_exact_persisted_identity(
    tmp_path: Path,
) -> None:
    parent_path, root_path = _tree(tmp_path)
    manifest_path, manifest_identity, digest = _write_manifest(
        root_path, "tree.manifest"
    )
    secret = root_path / "private/ca.key"
    original = secret.stat()
    replacement = b"changed key bytes\n"
    assert len(replacement) == original.st_size
    secret.write_bytes(replacement)
    os.utime(secret, ns=(original.st_atime_ns, original.st_mtime_ns))

    with (
        OpenedDirectory(parent_path) as parent,
        OpenedDirectory(root_path) as root,
        OpenedFile(manifest_path) as manifest,
        pytest.raises(TreeManifestError, match="member identity"),
    ):
        validate_tree_manifest(
            root,
            parent,
            "tree",
            manifest,
            manifest_identity,
            digest,
            "tree.manifest",
        )


def test_manifest_enforces_identity_digest_and_bounds(tmp_path: Path) -> None:
    parent_path, root_path = _tree(tmp_path)
    manifest_path, manifest_identity, digest = _write_manifest(
        root_path, "tree.manifest"
    )
    with (
        OpenedDirectory(parent_path) as parent,
        OpenedDirectory(root_path) as root,
        OpenedFile(manifest_path) as manifest,
    ):
        with pytest.raises(TreeManifestError, match="identity"):
            validate_tree_manifest(
                root,
                parent,
                "tree",
                manifest,
                replace(manifest_identity, mtime_ns=manifest_identity.mtime_ns + 1),
                digest,
                "tree.manifest",
            )
        with pytest.raises(TreeManifestError, match="digest changed"):
            validate_tree_manifest(
                root,
                parent,
                "tree",
                manifest,
                manifest_identity,
                "0" * 64,
                "tree.manifest",
            )
        with pytest.raises(FilesystemReadLimitError):
            validate_tree_manifest(
                root,
                parent,
                "tree",
                manifest,
                manifest_identity,
                digest,
                "tree.manifest",
                max_bytes=manifest_identity.size - 1,
            )
        with pytest.raises(TreeManifestError, match="entry bound"):
            validate_tree_manifest(
                root,
                parent,
                "tree",
                manifest,
                manifest_identity,
                digest,
                "tree.manifest",
                max_entries=1,
            )


def test_validation_rejects_symlinks_and_cross_device_members(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parent_path, root_path = _tree(tmp_path)
    manifest_path, manifest_identity, digest = _write_manifest(
        root_path, "tree.manifest"
    )
    link = root_path / "link"
    link.symlink_to("public/certificate.pem")
    with (
        OpenedDirectory(parent_path) as parent,
        OpenedDirectory(root_path) as root,
        OpenedFile(manifest_path) as manifest,
        pytest.raises(PublicationTreeError),
    ):
        validate_tree_manifest(
            root,
            parent,
            "tree",
            manifest,
            manifest_identity,
            digest,
            "tree.manifest",
        )

    link.unlink()
    manifest_path, manifest_identity, digest = _write_manifest(
        root_path, "tree.manifest"
    )
    real_tree_stat = publication._tree_stat

    def cross_device(parent_fd: int, name: str):
        identity = real_tree_stat(parent_fd, name)
        if name == "public" and isinstance(identity, FileIdentity):
            return replace(identity, dev=identity.dev + 1)
        return identity

    monkeypatch.setattr(publication, "_tree_stat", cross_device)
    with (
        OpenedDirectory(parent_path) as parent,
        OpenedDirectory(root_path) as root,
        OpenedFile(manifest_path) as manifest,
        pytest.raises(PublicationTreeError),
    ):
        validate_tree_manifest(
            root,
            parent,
            "tree",
            manifest,
            manifest_identity,
            digest,
            "tree.manifest",
        )
