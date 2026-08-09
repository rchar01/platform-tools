"""Validation of final-Bash PKI tree and provenance manifests."""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from enum import Enum

from .filesystem import (
    DirectoryIdentity,
    FileIdentity,
    FileObjectState,
    OpenedDirectory,
    OpenedFile,
    open_descendant_file,
    walk_metadata,
)
from .persisted_identity import (
    PersistedIdentityError,
    parse_directory_identity,
    parse_file_identity,
    parse_file_object_state,
)
from .publication import TreeReadiness, fsync_tree, remove_exact_tree


MAX_TREE_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_TREE_MANIFEST_ENTRIES = 65_536
MAX_TREE_MANIFEST_DEPTH = 64
_SHA256 = re.compile(r"[0-9a-f]{64}", re.ASCII)


class TreeManifestError(ValueError):
    """A tree manifest or the tree it describes is not exact and complete."""


class _DigestPolicy(Enum):
    TREE = "tree"
    PROVENANCE = "provenance"


@dataclass(frozen=True, slots=True)
class _ManifestEntry:
    relative: tuple[str, ...]
    identity: FileIdentity | DirectoryIdentity
    digest: bytes | None
    secret: bool


def _positive_bound(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{label} must be a positive integer")
    return value


def _expected_file_identity(
    value: str | FileIdentity | FileObjectState,
) -> FileIdentity | FileObjectState:
    if isinstance(value, str):
        try:
            parsed = parse_file_identity(value)
            assert isinstance(parsed, FileIdentity)
            return parsed
        except PersistedIdentityError:
            parsed_state = parse_file_object_state(value)
            assert isinstance(parsed_state, FileObjectState)
            return parsed_state
    if not isinstance(value, (FileIdentity, FileObjectState)):
        raise TypeError(
            "expected_manifest_identity must be persisted text, a FileIdentity, "
            "or a FileObjectState"
        )
    return value


def _expected_directory_identity(
    value: str | DirectoryIdentity,
) -> DirectoryIdentity:
    if isinstance(value, str):
        parsed = parse_directory_identity(value)
        assert isinstance(parsed, DirectoryIdentity)
        return parsed
    if not isinstance(value, DirectoryIdentity):
        raise TypeError(
            "expected_root_identity must be persisted text or a DirectoryIdentity"
        )
    return value


def _matches_file_identity(
    actual: FileIdentity,
    expected: FileIdentity | FileObjectState,
) -> bool:
    if isinstance(expected, FileIdentity):
        return actual == expected
    return actual.state == expected


def _sha256(value: str, label: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be text")
    if _SHA256.fullmatch(value) is None:
        raise TreeManifestError(f"{label} is not a canonical SHA-256 digest")
    return value


def _relative(raw: bytes, max_depth: int) -> tuple[str, ...]:
    if (
        not raw
        or raw.startswith(b"/")
        or b"\0" in raw
        or b"|" in raw
        or b"\n" in raw
    ):
        raise TreeManifestError("tree manifest contains an unsafe relative path")
    parts = raw.split(b"/")
    if any(part in (b"", b".", b"..") for part in parts):
        raise TreeManifestError("tree manifest contains path traversal")
    if len(parts) > max_depth:
        raise TreeManifestError("tree manifest path exceeds the depth bound")
    return tuple(os.fsdecode(part) for part in parts)


def _is_secret(relative: tuple[str, ...], policy: _DigestPolicy) -> bool:
    encoded = b"/".join(os.fsencode(part) for part in relative)
    if policy is _DigestPolicy.PROVENANCE:
        return encoded.startswith(b"quarantine/")
    return (
        b"private" in (os.fsencode(part) for part in relative[:-1])
        or encoded.endswith(b".key")
        or b"passphrase" in encoded
    )


def _parse_manifest(
    data: bytes,
    policy: _DigestPolicy,
    *,
    max_entries: int,
    max_depth: int,
) -> tuple[_ManifestEntry, ...]:
    if not data:
        return ()
    if not data.endswith(b"\n"):
        raise TreeManifestError("tree manifest must end with a newline")

    lines = data[:-1].split(b"\n")
    if len(lines) > max_entries:
        raise TreeManifestError("tree manifest exceeds the entry bound")
    entries: list[_ManifestEntry] = []
    previous: bytes | None = None
    seen: set[bytes] = set()
    for line in lines:
        fields = line.split(b"|")
        if len(fields) != 4:
            raise TreeManifestError("tree manifest contains a malformed row")
        raw_type, raw_relative, raw_identity, raw_digest = fields
        relative = _relative(raw_relative, max_depth)
        if raw_relative in seen:
            raise TreeManifestError("tree manifest contains a duplicate member")
        if previous is not None and raw_relative <= previous:
            raise TreeManifestError("tree manifest members are not in C-locale order")
        seen.add(raw_relative)
        previous = raw_relative

        try:
            identity_text = raw_identity.decode("ascii")
        except UnicodeDecodeError:
            raise TreeManifestError("tree manifest identity is not ASCII") from None
        if raw_type == b"directory":
            try:
                identity = parse_directory_identity(identity_text)
            except PersistedIdentityError:
                raise TreeManifestError(
                    "tree manifest directory identity is invalid"
                ) from None
            assert isinstance(identity, DirectoryIdentity)
            if raw_digest != b"-":
                raise TreeManifestError("tree manifest directory digest is invalid")
            digest = None
            secret = False
        elif raw_type in (b"regular file", b"regular empty file"):
            try:
                parsed = parse_file_identity(identity_text)
            except PersistedIdentityError:
                raise TreeManifestError(
                    "tree manifest file identity is invalid"
                ) from None
            assert isinstance(parsed, FileIdentity)
            expected_type = b"regular empty file" if parsed.size == 0 else b"regular file"
            if raw_type != expected_type:
                raise TreeManifestError("tree manifest file type is inconsistent")
            identity = parsed
            secret = _is_secret(relative, policy)
            if secret:
                if raw_digest != b"secret":
                    raise TreeManifestError("tree manifest secret digest is invalid")
                digest = None
            else:
                try:
                    digest_text = raw_digest.decode("ascii")
                except UnicodeDecodeError:
                    raise TreeManifestError("tree manifest digest is not ASCII") from None
                if _SHA256.fullmatch(digest_text) is None:
                    raise TreeManifestError("tree manifest file digest is invalid")
                digest = bytes.fromhex(digest_text)
        else:
            raise TreeManifestError("tree manifest object type is unsupported")
        entries.append(_ManifestEntry(relative, identity, digest, secret))
    return tuple(entries)


def _flatten_readiness(
    entries: tuple[object, ...],
    prefix: tuple[str, ...] = (),
) -> list[tuple[tuple[str, ...], FileIdentity, bytes | None]]:
    flattened = []
    for entry in entries:
        relative = (*prefix, entry.name)  # type: ignore[attr-defined]
        identity = entry.identity  # type: ignore[attr-defined]
        if not isinstance(identity, FileIdentity):
            raise TreeManifestError("tree readiness contains an unsupported object")
        digest = entry.digest  # type: ignore[attr-defined]
        flattened.append((relative, identity, digest))
        if identity.kind == "directory":
            flattened.extend(
                _flatten_readiness(entry.children, relative)  # type: ignore[attr-defined]
            )
    flattened.sort(key=lambda item: b"/".join(os.fsencode(part) for part in item[0]))
    return flattened


def _validate_tree_bounds(
    root: OpenedDirectory,
    excluded: tuple[str, ...] | None,
    *,
    max_entries: int,
    max_depth: int,
) -> None:
    count = 0
    root_device = root.identity.dev
    for entry in walk_metadata(root, xdev=True):
        if not entry.relative:
            continue
        if entry.dev != root_device:
            raise TreeManifestError("tree contains a cross-device member")
        if len(entry.relative) > max_depth:
            raise TreeManifestError("tree exceeds the manifest depth bound")
        if entry.relative == excluded:
            continue
        count += 1
        if count > max_entries:
            raise TreeManifestError("tree exceeds the manifest entry bound")


def _validate_entries(
    expected: tuple[_ManifestEntry, ...],
    readiness: TreeReadiness,
    excluded: tuple[str, ...] | None,
    *,
    max_entries: int,
    max_depth: int,
) -> None:
    actual = [
        item
        for item in _flatten_readiness(readiness.snapshot)
        if item[0] != excluded
    ]
    if len(actual) > max_entries:
        raise TreeManifestError("tree exceeds the manifest entry bound")
    if any(len(relative) > max_depth for relative, _identity, _digest in actual):
        raise TreeManifestError("tree exceeds the manifest depth bound")
    if len(actual) != len(expected):
        raise TreeManifestError("tree members do not match the manifest")

    for manifest_entry, (relative, identity, digest) in zip(expected, actual):
        if relative != manifest_entry.relative:
            raise TreeManifestError("tree members do not match the manifest")
        persisted = manifest_entry.identity
        if isinstance(persisted, DirectoryIdentity):
            identity_matches = identity.kind == "directory" and identity.directory == persisted
        else:
            identity_matches = identity == persisted
        if not identity_matches:
            raise TreeManifestError("tree member identity does not match the manifest")
        if not manifest_entry.secret and digest != manifest_entry.digest:
            raise TreeManifestError("tree member digest does not match the manifest")


def _validate_manifest(
    root: OpenedDirectory,
    publication_parent: OpenedDirectory,
    root_name: str | os.PathLike[str],
    manifest: OpenedFile,
    expected_manifest_identity: str | FileIdentity | FileObjectState,
    expected_manifest_sha256: str,
    policy: _DigestPolicy,
    excluded: str | None,
    *,
    max_bytes: int,
    max_entries: int,
    max_depth: int,
) -> TreeReadiness:
    if not isinstance(root, OpenedDirectory):
        raise TypeError("root must be an OpenedDirectory")
    if not isinstance(publication_parent, OpenedDirectory):
        raise TypeError("publication_parent must be an OpenedDirectory")
    if not isinstance(manifest, OpenedFile):
        raise TypeError("manifest must be an OpenedFile")
    max_bytes = _positive_bound(max_bytes, "max_bytes")
    max_entries = _positive_bound(max_entries, "max_entries")
    max_depth = _positive_bound(max_depth, "max_depth")
    expected_identity = _expected_file_identity(expected_manifest_identity)
    expected_digest = _sha256(expected_manifest_sha256, "expected_manifest_sha256")
    if not _matches_file_identity(manifest.identity, expected_identity):
        raise TreeManifestError("tree manifest identity changed")

    data = manifest.read(max_bytes)
    if hashlib.sha256(data).hexdigest() != expected_digest:
        raise TreeManifestError("tree manifest digest changed")
    entries = _parse_manifest(
        data,
        policy,
        max_entries=max_entries,
        max_depth=max_depth,
    )
    excluded_components = None
    if excluded is not None:
        if not isinstance(excluded, str):
            raise TypeError("excluded must be text or None")
        excluded_components = _relative(os.fsencode(excluded), max_depth)
        with open_descendant_file(
            root,
            excluded_components,
            expected_identity=manifest.identity,
        ) as in_tree_manifest:
            in_tree_manifest.recheck()
        manifest.recheck()

    _validate_tree_bounds(
        root,
        excluded_components,
        max_entries=max_entries,
        max_depth=max_depth,
    )
    readiness = fsync_tree(root, publication_parent, root_name)
    _validate_entries(
        entries,
        readiness,
        excluded_components,
        max_entries=max_entries,
        max_depth=max_depth,
    )
    manifest.recheck()
    root.recheck()
    publication_parent.recheck()
    return readiness


def validate_tree_manifest(
    root: OpenedDirectory,
    publication_parent: OpenedDirectory,
    root_name: str | os.PathLike[str],
    manifest: OpenedFile,
    expected_manifest_identity: str | FileIdentity | FileObjectState,
    expected_manifest_sha256: str,
    excluded: str | None = None,
    *,
    max_bytes: int = MAX_TREE_MANIFEST_BYTES,
    max_entries: int = MAX_TREE_MANIFEST_ENTRIES,
    max_depth: int = MAX_TREE_MANIFEST_DEPTH,
) -> TreeReadiness:
    """Validate one final-Bash tree manifest and return exact cleanup readiness."""

    return _validate_manifest(
        root,
        publication_parent,
        root_name,
        manifest,
        expected_manifest_identity,
        expected_manifest_sha256,
        _DigestPolicy.TREE,
        excluded,
        max_bytes=max_bytes,
        max_entries=max_entries,
        max_depth=max_depth,
    )


def validate_provenance_manifest(
    root: OpenedDirectory,
    publication_parent: OpenedDirectory,
    root_name: str | os.PathLike[str],
    manifest: OpenedFile,
    expected_manifest_identity: str | FileIdentity | FileObjectState,
    expected_manifest_sha256: str,
    *,
    max_bytes: int = MAX_TREE_MANIFEST_BYTES,
    max_entries: int = MAX_TREE_MANIFEST_ENTRIES,
    max_depth: int = MAX_TREE_MANIFEST_DEPTH,
) -> TreeReadiness:
    """Validate final-Bash migration provenance, excluding its own manifest."""

    return _validate_manifest(
        root,
        publication_parent,
        root_name,
        manifest,
        expected_manifest_identity,
        expected_manifest_sha256,
        _DigestPolicy.PROVENANCE,
        "provenance-manifest",
        max_bytes=max_bytes,
        max_entries=max_entries,
        max_depth=max_depth,
    )


def remove_manifested_tree(
    parent: OpenedDirectory,
    root_name: str | os.PathLike[str],
    expected_root_identity: str | DirectoryIdentity,
    manifest: OpenedFile,
    expected_manifest_identity: str | FileIdentity | FileObjectState,
    expected_manifest_sha256: str,
    excluded: str | None = None,
    *,
    max_bytes: int = MAX_TREE_MANIFEST_BYTES,
    max_entries: int = MAX_TREE_MANIFEST_ENTRIES,
    max_depth: int = MAX_TREE_MANIFEST_DEPTH,
) -> None:
    """Validate and remove one exact final-Bash manifested directory tree."""

    if not isinstance(parent, OpenedDirectory):
        raise TypeError("parent must be an OpenedDirectory")
    directory_identity = _expected_directory_identity(expected_root_identity)
    root_identity: FileIdentity | None = None
    readiness: TreeReadiness | None = None
    with parent.open_directory(
        root_name,
        expected_identity=directory_identity,
    ) as root:
        root_identity = root.identity
        readiness = validate_tree_manifest(
            root,
            parent,
            root_name,
            manifest,
            expected_manifest_identity,
            expected_manifest_sha256,
            excluded,
            max_bytes=max_bytes,
            max_entries=max_entries,
            max_depth=max_depth,
        )
        root.recheck()
    assert root_identity is not None and readiness is not None
    remove_exact_tree(parent, root_name, root_identity, readiness)
