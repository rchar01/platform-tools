"""Publish and download validated host-local PKI packages through GitLab."""

from __future__ import annotations

import base64
import binascii
import ctypes
import errno
import hashlib
import ipaddress
import json
import os
import re
import secrets
import ssl
import stat
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any, NoReturn

from .errors import ApplicationError
from .parser import ParseResult


STATUSES = (
    "default",
    "hidden",
    "processing",
    "error",
    "pending_destruction",
    "deprecated",
)
TRUST_NAMES = (
    "policy",
    "requesters.allowed_signers",
    "approvers.allowed_signers",
    "responses.allowed_signers",
    "deployers.allowed_signers",
)
REQUEST_FILES = (
    "tls.csr",
    "request",
    "request.sig",
    "collection-receipt",
)
PACKAGE_FILES = (*REQUEST_FILES, "stage-manifest")
STAGE_PAYLOADS = {
    "request": REQUEST_FILES,
    "approval": ("approval", "approval.sig"),
    "response": (
        "artifact",
        "tls.crt",
        "ca-chain.crt",
        "fullchain.crt",
        "response",
        "response.sig",
    ),
    "evidence": (
        "deployment",
        "deployment.sig",
        "validation-boundary",
        "validation-result",
        "validation-result.sig",
    ),
    "outcome": (
        "outcome",
        "outcome.sig",
        "deployment",
        "deployment.sig",
        "deployers.allowed_signers",
        "decision",
    ),
}
REQUEST_FIELDS = (
    "schema",
    "request_id",
    "nonce",
    "created_epoch",
    "expires_epoch",
    "operation",
    "service",
    "target",
    "requester_principal",
    "inventory_sha256",
    "csr_sha256",
    "csr_spki_sha256",
    "current_cert_sha256",
    "profile",
    "response_principal",
)
APPROVAL_FIELDS = (
    "schema",
    "request_id",
    "nonce",
    "created_epoch",
    "expires_epoch",
    "approver_principal",
    "request_sha256",
    "csr_sha256",
    "inventory_sha256",
    "operation",
    "service",
    "target",
    "profile",
)
RESPONSE_FIELDS = (
    "schema",
    "request_id",
    "nonce",
    "operation",
    "service",
    "target",
    "request_sha256",
    "approval_sha256",
    "inventory_sha256",
    "csr_sha256",
    "csr_spki_sha256",
    "certificate_sha256",
    "certificate_spki_sha256",
    "chain_sha256",
    "issuer_root",
    "issuer_intermediate",
    "serial",
    "not_before_epoch",
    "not_after_epoch",
    "candidate_state",
    "response_principal",
    "created_epoch",
)
ARTIFACT_FIELDS = (
    "schema",
    "kind",
    "service",
    "request_id",
    "operation",
    "target",
    "source_kind",
    "source_response_sha256",
    "source_response_signature_sha256",
    "certificate_sha256",
    "certificate_spki_sha256",
    "chain_sha256",
    "fullchain_sha256",
    "issuer_root",
    "issuer_intermediate",
    "serial",
    "not_before_epoch",
    "not_after_epoch",
    "candidate_state",
    "deployment_state",
    "response_principal",
    "created_epoch",
)
DEPLOYMENT_FIELDS = tuple(
    """schema request_id nonce operation service target request_sha256 response_sha256
    response_signature_sha256 candidate_sha256 artifact_request_id
    artifact_manifest_sha256 certificate_sha256 certificate_spki_sha256
    chain_sha256 fullchain_sha256 action result local_certificate_sha256
    local_key_spki_sha256 local_key_certificate_match served_certificate_sha256
    served_intermediate_sha256 validation_boundary_sha256 validation_result
    activation_epoch validation_epoch rollback_state rollback_hold_until_epoch
    deployment_principal created_epoch expires_epoch""".split()
)
VALIDATION_BOUNDARY_FIELDS = (
    "schema",
    "kind",
    "service",
    "target",
    "local_validator",
    "remote_validator",
    "endpoint",
    "local_check",
    "remote_check",
)
VALIDATION_RESULT_FIELDS = tuple(
    """schema kind service target request_id artifact_manifest_sha256
    validation_boundary_sha256 action result local_validator remote_validator
    endpoint local_service_result local_tls_result remote_tls_result
    remote_application_result remote_http_status remote_api_version
    remote_auth_challenge served_certificate_sha256 served_intermediate_sha256
    activation_epoch validation_epoch deployment_sha256""".split()
)
DECISION_FIELDS = tuple(
    """schema action state service target request_id operation request_sha256
    response_sha256 response_signature_sha256 candidate_sha256
    artifact_manifest_sha256 certificate_sha256 certificate_spki_sha256
    chain_sha256 fullchain_sha256 deployment_sha256 deployment_signature_sha256
    deployers_sha256 predecessor_kind predecessor_request_id
    predecessor_certificate_sha256 predecessor_certificate_spki_sha256
    predecessor_intermediate_sha256 predecessor_response_sha256
    predecessor_artifact_manifest_sha256 predecessor_deployment_sha256
    predecessor_decision_sha256 resulting_active_request_id created_epoch""".split()
)
OUTCOME_FIELDS = tuple(
    """schema kind service target request_id operation request_sha256
    response_sha256 response_signature_sha256 candidate_sha256
    artifact_manifest_sha256 certificate_sha256 certificate_spki_sha256 chain_sha256
    fullchain_sha256 deployment_sha256 deployment_signature_sha256 deployers_sha256
    decision_sha256 action state resulting_active_request_id created_epoch
    outcome_principal""".split()
)
RECEIPT_FIELDS = (
    "schema",
    "kind",
    "service",
    "target",
    "request_id",
    "transport",
    "transport_host_key_sha256",
    "csr_sha256",
    "request_sha256",
    "request_signature_sha256",
    "trust_policy_sha256",
    "request_trust_sha256",
    "approval_trust_sha256",
    "response_trust_sha256",
    "deployment_trust_sha256",
    "request_principal",
    "request_namespace",
    "collected_epoch",
    "verification_result",
)
POLICY_FIELDS = (
    "schema",
    "request_namespace",
    "approval_namespace",
    "response_namespace",
    "deployment_namespace",
    "request_max_age_seconds",
    "sole_operator_min_delay_seconds",
    "approval_max_age_seconds",
    "deployment_max_age_seconds",
    "clock_skew_seconds",
    "approver_principal",
    "response_principal",
)
PROJECT_FIELDS = (
    "schema",
    "kind",
    "origin",
    "project_id",
    "project_path",
    "gitlab_version",
)
INVENTORY_FIXED_FIELDS = (
    "schema",
    "kind",
    "service",
    "target",
    "inventory_sha256",
    "common_name",
    "dns_san_count",
)
MANIFEST_FIELDS = (
    "schema",
    "kind",
    "stage",
    "service",
    "request_id",
    "package_version",
    "payload_count",
)
MAX_FILE_SIZE = {
    "tls.csr": 65536,
    "request": 16384,
    "request.sig": 16384,
    "collection-receipt": 16384,
    "approval": 16384,
    "approval.sig": 16384,
    "artifact": 16384,
    "tls.crt": 65536,
    "ca-chain.crt": 131072,
    "fullchain.crt": 131072,
    "response": 16384,
    "response.sig": 16384,
    "deployment": 32768,
    "deployment.sig": 16384,
    "validation-boundary": 16384,
    "validation-result": 32768,
    "validation-result.sig": 16384,
    "outcome": 16384,
    "outcome.sig": 16384,
    "deployers.allowed_signers": 65536,
    "decision": 32768,
    "stage-manifest": 65536,
}
HEX_32 = re.compile(r"[0-9a-f]{32}\Z")
HEX_64 = re.compile(r"[0-9a-f]{64}\Z")
SERVICE = re.compile(r"[a-z0-9][a-z0-9-]{0,62}\Z")
PRINCIPAL = re.compile(r"[a-z0-9][a-z0-9.-]{0,252}\Z")
PROJECT_PATH = re.compile(
    r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+\Z"
)


def _source_checkout_root(module_path: Path) -> Path | None:
    """Identify a source checkout without treating an install prefix as one."""

    package_directory = module_path.parent
    archive_or_source = package_directory.parent
    if archive_or_source.is_file():
        if archive_or_source.parent.name != "bin":
            return None
        candidate = archive_or_source.parent.parent
    elif archive_or_source.name == "src":
        candidate = archive_or_source.parent
    else:
        return None
    expected_module = candidate / "src/platform_pki/gitlab_package.py"
    if not (candidate / "Makefile").is_file() or not expected_module.is_file():
        return None
    return candidate.resolve()


REPOSITORY_ROOT = _source_checkout_root(Path(__file__))


def _inside_public_repository(path: Path) -> bool:
    return REPOSITORY_ROOT is not None and (
        path == REPOSITORY_ROOT or REPOSITORY_ROOT in path.parents
    )


class PackageError(RuntimeError):
    pass


def fail(message: str) -> NoReturn:
    raise PackageError(message)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class StageSpec:
    name: str
    payloads: tuple[str, ...]
    version_digest_file: str | None

    @property
    def package_files(self) -> tuple[str, ...]:
        return (*self.payloads, "stage-manifest")

    def package_name(self, service: str) -> str:
        return f"pki-exchange-{self.name}-{service}"

    def package_version(self, request_id: str, payloads: dict[str, bytes]) -> str:
        if self.version_digest_file is None:
            return request_id
        return f"{request_id}-{sha256(payloads[self.version_digest_file])}"


STAGE_SPECS = {
    name: StageSpec(
        name,
        payloads,
        {
            "approval": "approval",
            "evidence": "deployment",
            "outcome": "outcome",
        }.get(name),
    )
    for name, payloads in STAGE_PAYLOADS.items()
}


def parse_record(data: bytes, fields: tuple[str, ...], label: str) -> dict[str, str]:
    if not data.endswith(b"\n") or b"\r" in data or b"\x00" in data:
        fail(f"{label} is not canonical LF-terminated text")
    try:
        lines = data.decode("ascii").splitlines()
    except UnicodeDecodeError:
        fail(f"{label} is not printable ASCII")
    if len(lines) != len(fields):
        fail(f"{label} has an unexpected field count")
    result: dict[str, str] = {}
    for expected, line in zip(fields, lines, strict=True):
        if "=" not in line:
            fail(f"{label} contains a malformed field")
        key, value = line.split("=", 1)
        if key != expected or not value:
            fail(f"{label} contains an unexpected or empty field")
        result[key] = value
    return result


def canonical_epoch(value: str, label: str) -> int:
    if not re.fullmatch(r"0|[1-9][0-9]*", value):
        fail(f"{label} is not a canonical decimal epoch")
    parsed = int(value)
    if parsed <= 0:
        fail(f"{label} must be positive")
    return parsed


def decode_ssh_string(data: bytes, offset: int, label: str) -> tuple[bytes, int]:
    if offset + 4 > len(data):
        fail(f"{label} contains truncated SSH key data")
    length = int.from_bytes(data[offset : offset + 4], "big")
    offset += 4
    if length > len(data) - offset:
        fail(f"{label} contains truncated SSH key data")
    return data[offset : offset + length], offset + length


def decode_single_armor(data: bytes, kind: str, label: str) -> bytes:
    begin = f"-----BEGIN {kind}-----\n".encode("ascii")
    end = f"-----END {kind}-----\n".encode("ascii")
    lines = data.splitlines(keepends=True)
    if (
        len(lines) < 3
        or lines[0] != begin
        or lines[-1] != end
        or any(not line.endswith(b"\n") for line in lines)
    ):
        fail(f"{label} is not one exact ASCII-armored object")
    body_lines = [line[:-1] for line in lines[1:-1]]
    if not body_lines or any(
        not line or re.fullmatch(rb"[A-Za-z0-9+/]+={0,2}", line) is None
        for line in body_lines
    ):
        fail(f"{label} contains malformed ASCII armor")
    encoded = b"".join(body_lines)
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        fail(f"{label} contains malformed ASCII armor")
    if not decoded or base64.b64encode(decoded) != encoded:
        fail(f"{label} contains noncanonical ASCII armor")
    return decoded


def validate_der_sequence(data: bytes, label: str) -> None:
    if len(data) < 2 or data[0] != 0x30:
        fail(f"{label} is not one DER sequence")
    first_length = data[1]
    if first_length < 0x80:
        content_length = first_length
        header_length = 2
    else:
        length_octets = first_length & 0x7F
        if (
            length_octets == 0
            or length_octets > len(data) - 2
            or data[2] == 0
        ):
            fail(f"{label} has a malformed DER length")
        content_length = int.from_bytes(data[2 : 2 + length_octets], "big")
        header_length = 2 + length_octets
        if content_length < 0x80:
            fail(f"{label} has a noncanonical DER length")
    if header_length + content_length != len(data):
        fail(f"{label} contains trailing or truncated DER data")


def validate_ssh_signature_container(
    data: bytes, label: str = "request signature"
) -> None:
    decoded = decode_single_armor(data, "SSH SIGNATURE", label)
    if len(decoded) < 10 or decoded[:6] != b"SSHSIG":
        fail(f"{label} has an invalid SSHSIG header")
    if int.from_bytes(decoded[6:10], "big") != 1:
        fail(f"{label} has an unsupported SSHSIG version")
    offset = 10
    for _ in range(5):
        _, offset = decode_ssh_string(decoded, offset, label)
    if offset != len(decoded):
        fail(f"{label} contains trailing SSHSIG data")


def parse_allowed_signers(data: bytes, label: str) -> dict[str, tuple[str, str]]:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        fail(f"{label} is not ASCII")
    if not text.endswith("\n") or "\r" in text or "\x00" in text:
        fail(f"{label} is not canonical LF-terminated text")
    records: dict[str, tuple[str, str]] = {}
    for line in text.splitlines():
        parts = line.split(" ")
        if (
            len(parts) != 3
            or not PRINCIPAL.fullmatch(parts[0])
            or parts[1] != "ssh-ed25519"
        ):
            fail(f"{label} contains a noncanonical signer record")
        try:
            decoded = base64.b64decode(parts[2], validate=True)
        except (binascii.Error, ValueError):
            fail(f"{label} contains invalid key data")
        if base64.b64encode(decoded).decode("ascii") != parts[2] or parts[0] in records:
            fail(f"{label} contains duplicate or noncanonical key data")
        algorithm, offset = decode_ssh_string(decoded, 0, label)
        public_key, offset = decode_ssh_string(decoded, offset, label)
        if algorithm != b"ssh-ed25519" or len(public_key) != 32 or offset != len(decoded):
            fail(f"{label} contains an invalid Ed25519 OpenSSH public-key blob")
        records[parts[0]] = (parts[1], parts[2])
    if not records:
        fail(f"{label} is empty")
    return records


def validate_frozen_trust(
    policy: dict[str, str],
    trust_data: dict[str, bytes],
    *,
    target: str,
    response_principal: str,
) -> None:
    expected_policy = {
        "schema": "2",
        "request_namespace": "platform-pki-csr-request-v1",
        "approval_namespace": "platform-pki-csr-approval-v1",
        "response_namespace": "platform-pki-csr-response-v1",
        "deployment_namespace": "platform-pki-csr-deployment-v1",
        "request_max_age_seconds": "604800",
        "sole_operator_min_delay_seconds": "86400",
        "approval_max_age_seconds": "86400",
        "deployment_max_age_seconds": "86400",
        "clock_skew_seconds": "300",
    }
    if any(policy[key] != value for key, value in expected_policy.items()):
        fail("controller trust policy does not match frozen schema 2")
    if (
        not PRINCIPAL.fullmatch(policy["approver_principal"])
        or not PRINCIPAL.fullmatch(policy["response_principal"])
        or policy["response_principal"] != response_principal
    ):
        fail("controller trust policy principals are invalid")
    requester_records = parse_allowed_signers(
        trust_data["requesters.allowed_signers"], "requester trust"
    )
    approver_records = parse_allowed_signers(
        trust_data["approvers.allowed_signers"], "approver trust"
    )
    response_records = parse_allowed_signers(
        trust_data["responses.allowed_signers"], "response trust"
    )
    deployment_records = parse_allowed_signers(
        trust_data["deployers.allowed_signers"], "deployment trust"
    )
    if target not in requester_records or target not in deployment_records:
        fail("target is absent from frozen requester or deployment trust")
    if set(approver_records) != {policy["approver_principal"]}:
        fail("frozen approver trust does not contain exactly the policy principal")
    if set(response_records) != {response_principal}:
        fail("frozen response trust does not contain exactly the policy principal")


def validate_dns(value: str, label: str) -> None:
    if len(value) > 253 or value.endswith(".") or not value.isascii():
        fail(f"{label} is not a canonical DNS name")
    labels = value.split(".")
    if any(
        not re.fullmatch(
            r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", part
        )
        for part in labels
    ):
        fail(f"{label} is not a canonical DNS name")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return
    fail(f"{label} is an IP address, not a DNS name")


def validate_ipv4(value: str, label: str) -> None:
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        fail(f"{label} is not a canonical IPv4 address")
    if not isinstance(parsed, ipaddress.IPv4Address) or str(parsed) != value:
        fail(f"{label} is not a canonical IPv4 address")


@dataclass
class PinnedDirectory:
    path: Path
    descriptor: int
    identity: tuple[int, int]
    owner: int
    mode: int

    @classmethod
    def open(cls, path: Path, *, owner: int, mode: int = 0o700) -> PinnedDirectory:
        if not path.is_absolute():
            fail(f"directory path must be absolute: {path}")
        try:
            descriptor = os.open(
                path,
                os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
            )
        except OSError as error:
            fail(f"cannot open protected directory {path}: {error.strerror}")
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISDIR(metadata.st_mode):
                fail(f"protected path is not a directory: {path}")
            if metadata.st_uid != owner or stat.S_IMODE(metadata.st_mode) != mode:
                fail(f"protected directory has unsafe owner or mode: {path}")
            path_metadata = os.lstat(path)
            identity = (metadata.st_dev, metadata.st_ino)
            if (path_metadata.st_dev, path_metadata.st_ino) != identity:
                fail(f"protected directory identity changed: {path}")
            return cls(
                path=path,
                descriptor=descriptor,
                identity=identity,
                owner=owner,
                mode=mode,
            )
        except Exception:
            os.close(descriptor)
            raise

    @classmethod
    def open_child(
        cls,
        parent: PinnedDirectory,
        name: str,
        *,
        owner: int,
        mode: int = 0o700,
    ) -> PinnedDirectory:
        if "/" in name or name in {"", ".", ".."}:
            fail("protected directory component is invalid")
        parent.recheck()
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=parent.descriptor,
            )
        except OSError as error:
            fail(f"cannot open protected directory component {name}: {error.strerror}")
        path = parent.path / name
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISDIR(metadata.st_mode):
                fail(f"protected path is not a directory: {path}")
            if metadata.st_uid != owner or stat.S_IMODE(metadata.st_mode) != mode:
                fail(f"protected directory has unsafe owner or mode: {path}")
            path_metadata = os.stat(
                name, dir_fd=parent.descriptor, follow_symlinks=False
            )
            identity = (metadata.st_dev, metadata.st_ino)
            if (path_metadata.st_dev, path_metadata.st_ino) != identity:
                fail(f"protected directory identity changed: {path}")
            return cls(
                path=path,
                descriptor=descriptor,
                identity=identity,
                owner=owner,
                mode=mode,
            )
        except Exception:
            os.close(descriptor)
            raise

    def names(self) -> set[str]:
        try:
            return set(os.listdir(self.descriptor))
        except OSError as error:
            fail(f"cannot enumerate protected directory {self.path}: {error.strerror}")

    def recheck(self) -> None:
        try:
            metadata = os.fstat(self.descriptor)
            path_metadata = os.lstat(self.path)
            identity = (metadata.st_dev, metadata.st_ino)
            if identity != self.identity or (
                path_metadata.st_dev,
                path_metadata.st_ino,
            ) != self.identity:
                fail(f"protected directory identity changed: {self.path}")
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != self.owner
                or stat.S_IMODE(metadata.st_mode) != self.mode
            ):
                fail(f"protected directory metadata changed: {self.path}")
        except OSError as error:
            fail(f"cannot recheck protected directory {self.path}: {error.strerror}")

    def close(self) -> None:
        os.close(self.descriptor)


@dataclass
class PinnedFile:
    directory: PinnedDirectory
    name: str
    descriptor: int
    identity: tuple[int, int]
    data: bytes
    owner: int
    modes: tuple[int, ...]

    @classmethod
    def open(
        cls,
        directory: PinnedDirectory,
        name: str,
        *,
        owner: int,
        modes: tuple[int, ...] = (0o600,),
        maximum: int,
    ) -> PinnedFile:
        if "/" in name or name in {"", ".", ".."}:
            fail("protected filename is invalid")
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory.descriptor,
            )
        except OSError as error:
            fail(f"cannot open protected file {name}: {error.strerror}")
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                fail(f"protected entry is not a regular file: {name}")
            if (
                metadata.st_uid != owner
                or stat.S_IMODE(metadata.st_mode) not in modes
                or metadata.st_nlink != 1
                or metadata.st_size <= 0
                or metadata.st_size > maximum
            ):
                fail(f"protected file has unsafe metadata: {name}")
            chunks: list[bytes] = []
            remaining = maximum + 1
            while remaining > 0:
                chunk = os.read(descriptor, min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
            if len(data) != metadata.st_size:
                fail(f"protected file changed while reading: {name}")
            identity = (metadata.st_dev, metadata.st_ino)
            path_metadata = os.stat(
                name, dir_fd=directory.descriptor, follow_symlinks=False
            )
            if (path_metadata.st_dev, path_metadata.st_ino) != identity:
                fail(f"protected file identity changed while reading: {name}")
            return cls(directory, name, descriptor, identity, data, owner, modes)
        except Exception:
            os.close(descriptor)
            raise

    def recheck(self) -> None:
        try:
            metadata = os.fstat(self.descriptor)
            path_metadata = os.stat(
                self.name,
                dir_fd=self.directory.descriptor,
                follow_symlinks=False,
            )
            if (
                (metadata.st_dev, metadata.st_ino) != self.identity
                or (path_metadata.st_dev, path_metadata.st_ino) != self.identity
                or metadata.st_size != len(self.data)
            ):
                fail(f"protected file identity changed: {self.name}")
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != self.owner
                or stat.S_IMODE(metadata.st_mode) not in self.modes
                or metadata.st_nlink != 1
            ):
                fail(f"protected file metadata changed: {self.name}")
            os.lseek(self.descriptor, 0, os.SEEK_SET)
            current = b""
            while chunk := os.read(self.descriptor, 65536):
                current += chunk
            if current != self.data:
                fail(f"protected file bytes changed: {self.name}")
        except OSError as error:
            fail(f"cannot recheck protected file {self.name}: {error.strerror}")

    def close(self) -> None:
        os.close(self.descriptor)


@dataclass
class PinnedAbsoluteFile:
    path: Path
    label: str
    descriptor: int
    identity: tuple[int, int]
    data: bytes
    directory_descriptors: list[int]
    directory_components: tuple[str, ...]
    directory_identities: tuple[tuple[int, int], ...]
    owners: tuple[int, ...]
    modes: tuple[int, ...]

    @classmethod
    def open(
        cls,
        path: Path,
        *,
        owners: tuple[int, ...],
        modes: tuple[int, ...],
        maximum: int,
        label: str,
    ) -> PinnedAbsoluteFile:
        if not path.is_absolute():
            fail(f"{label} path must be absolute")
        if any(component in {"", ".", ".."} for component in path.parts[1:]):
            fail(f"{label} path is not canonical")
        if _inside_public_repository(path):
            fail(f"{label} must be outside the public repository")
        directory_descriptors: list[int] = []
        directory_identities: list[tuple[int, int]] = []
        descriptor: int | None = None
        try:
            parent_descriptor = os.open(
                "/", os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
            )
            directory_descriptors.append(parent_descriptor)
            root_metadata = os.fstat(parent_descriptor)
            directory_identities.append((root_metadata.st_dev, root_metadata.st_ino))
            for component in path.parts[1:-1]:
                child_descriptor = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=parent_descriptor,
                )
                metadata = os.fstat(child_descriptor)
                if not stat.S_ISDIR(metadata.st_mode):
                    fail(f"{label} ancestor is not a directory")
                directory_descriptors.append(child_descriptor)
                directory_identities.append((metadata.st_dev, metadata.st_ino))
                parent_descriptor = child_descriptor
            descriptor = os.open(
                path.name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=parent_descriptor,
            )
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid not in owners
                or stat.S_IMODE(metadata.st_mode) not in modes
                or metadata.st_nlink != 1
                or metadata.st_size <= 0
                or metadata.st_size > maximum
            ):
                fail(f"{label} has unsafe metadata")
            data = b""
            while chunk := os.read(descriptor, 65536):
                data += chunk
                if len(data) > maximum:
                    fail(f"{label} exceeds its size limit")
            if len(data) != metadata.st_size:
                fail(f"{label} changed while reading")
            path_metadata = os.stat(
                path.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            identity = (metadata.st_dev, metadata.st_ino)
            if (path_metadata.st_dev, path_metadata.st_ino) != identity:
                fail(f"{label} identity changed")
            return cls(
                path=path,
                label=label,
                descriptor=descriptor,
                identity=identity,
                data=data,
                directory_descriptors=directory_descriptors,
                directory_components=tuple(path.parts[1:-1]),
                directory_identities=tuple(directory_identities),
                owners=owners,
                modes=modes,
            )
        except OSError as error:
            for opened in reversed(directory_descriptors):
                os.close(opened)
            if descriptor is not None:
                os.close(descriptor)
            fail(f"cannot open {label}: {error.strerror}")
        except Exception:
            for opened in reversed(directory_descriptors):
                os.close(opened)
            if descriptor is not None:
                os.close(descriptor)
            raise

    def recheck(self) -> None:
        try:
            for index, identity in enumerate(self.directory_identities):
                metadata = os.fstat(self.directory_descriptors[index])
                if (metadata.st_dev, metadata.st_ino) != identity:
                    fail(f"{self.label} ancestor identity changed")
                if index > 0:
                    path_metadata = os.stat(
                        self.directory_components[index - 1],
                        dir_fd=self.directory_descriptors[index - 1],
                        follow_symlinks=False,
                    )
                    if (path_metadata.st_dev, path_metadata.st_ino) != identity:
                        fail(f"{self.label} ancestor path changed")
            metadata = os.fstat(self.descriptor)
            path_metadata = os.stat(
                self.path.name,
                dir_fd=self.directory_descriptors[-1],
                follow_symlinks=False,
            )
            if (
                (metadata.st_dev, metadata.st_ino) != self.identity
                or (path_metadata.st_dev, path_metadata.st_ino) != self.identity
                or metadata.st_size != len(self.data)
            ):
                fail(f"{self.label} identity changed")
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid not in self.owners
                or stat.S_IMODE(metadata.st_mode) not in self.modes
                or metadata.st_nlink != 1
            ):
                fail(f"{self.label} metadata changed")
            os.lseek(self.descriptor, 0, os.SEEK_SET)
            current = b""
            while chunk := os.read(self.descriptor, 65536):
                current += chunk
            if current != self.data:
                fail(f"{self.label} bytes changed")
        except OSError as error:
            fail(f"cannot recheck {self.label}: {error.strerror}")

    def close(self) -> None:
        os.close(self.descriptor)
        for directory_descriptor in reversed(self.directory_descriptors):
            os.close(directory_descriptor)


def run_checked(argv: list[str], *, stdin: bytes, label: str) -> bytes:
    try:
        result = subprocess.run(
            argv,
            input=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        fail(f"{label} could not be executed")
    if result.returncode != 0:
        fail(f"{label} failed")
    return result.stdout


def validate_csr_profile(
    csr: bytes,
    *,
    common_name: str,
    dns_sans: list[str],
    ip_sans: list[str],
) -> bytes:
    csr_der = decode_single_armor(csr, "CERTIFICATE REQUEST", "CSR")
    validate_der_sequence(csr_der, "CSR")
    run_checked(
        ["openssl", "req", "-verify", "-noout"],
        stdin=csr,
        label="CSR verification",
    )
    subject = run_checked(
        ["openssl", "req", "-noout", "-subject", "-nameopt", "RFC2253"],
        stdin=csr,
        label="CSR subject inspection",
    ).decode("ascii", "strict").strip()
    text = run_checked(
        ["openssl", "req", "-noout", "-text"],
        stdin=csr,
        label="CSR profile inspection",
    ).decode("ascii", "strict")
    if subject != f"subject=CN={common_name}":
        fail("CSR common name differs from protected inventory input")
    if "Public-Key: (384 bit)" not in text or "ASN1 OID: secp384r1" not in text:
        fail("CSR key profile is not EC P-384")
    if (
        len(
            re.findall(
                r"^\s*Signature Algorithm: ecdsa-with-SHA384\s*$",
                text,
                re.MULTILINE,
            )
        )
        != 1
    ):
        fail("CSR signature profile is not SHA-384")
    lines = text.splitlines()
    try:
        attribute_start = lines.index("        Attributes:")
        signature_start = next(
            index
            for index, line in enumerate(
                lines[attribute_start + 1 :], attribute_start + 1
            )
            if line.startswith("    Signature Algorithm:")
        )
    except (ValueError, StopIteration):
        fail("CSR attribute structure is malformed")
    headers = [
        line.strip()
        for line in lines[attribute_start + 1 : signature_start]
        if line.startswith("            ") and not line.startswith("                ")
    ]
    if headers != ["Requested Extensions:"]:
        fail("CSR contains unexpected attributes")
    extension_headings = [
        line.strip()
        for line in lines[attribute_start + 1 : signature_start]
        if re.fullmatch(r" {16}\S.*:\s*", line)
    ]
    if extension_headings != ["X509v3 Subject Alternative Name:"]:
        fail("CSR contains unexpected requested extensions")
    san_index = next(
        (
            index
            for index, line in enumerate(lines)
            if "X509v3 Subject Alternative Name:" in line
        ),
        None,
    )
    if san_index is None or san_index + 1 >= len(lines):
        fail("CSR SAN extension is missing")
    san_values = [value.strip() for value in lines[san_index + 1].strip().split(",")]
    expected = [f"DNS:{value}" for value in dns_sans] + [
        f"IP Address:{value}" for value in ip_sans
    ]
    if san_values != expected:
        fail("CSR SANs differ from protected inventory input")
    csr_public = run_checked(
        ["openssl", "req", "-pubkey", "-noout"],
        stdin=csr,
        label="CSR public-key extraction",
    )
    csr_spki = run_checked(
        ["openssl", "pkey", "-pubin", "-outform", "DER"],
        stdin=csr_public,
        label="CSR SPKI conversion",
    )
    public_text = run_checked(
        ["openssl", "pkey", "-pubin", "-inform", "DER", "-text", "-noout"],
        stdin=csr_spki,
        label="CSR public-key profile validation",
    ).decode("ascii", "strict")
    if "ASN1 OID: secp384r1" not in public_text:
        fail("CSR public key is not EC P-384")
    return csr_spki


@dataclass(frozen=True)
class ProjectRecord:
    origin: str
    project_id: int
    project_path: str
    source: PinnedAbsoluteFile


def load_project_record(path: Path, uid: int) -> ProjectRecord:
    source = PinnedAbsoluteFile.open(
        path,
        owners=(uid,),
        modes=(0o400, 0o600),
        maximum=8192,
        label="GitLab exchange project record",
    )
    try:
        record = parse_record(
            source.data, PROJECT_FIELDS, "GitLab exchange project record"
        )
        if record["schema"] != "1" or record["kind"] != "pki-exchange-project":
            fail("GitLab exchange project record schema is unsupported")
        if not re.fullmatch(r"[1-9][0-9]*", record["project_id"]):
            fail("GitLab exchange project record has an invalid project ID")
        if (
            not PROJECT_PATH.fullmatch(record["project_path"])
            or any(
                part in {".", ".."} for part in record["project_path"].split("/")
            )
        ):
            fail("GitLab exchange project record has an invalid project path")
        if record["gitlab_version"] != "18.11.3-ce.0":
            fail("GitLab exchange project record does not pin 18.11.3-ce.0")
        parsed = urllib.parse.urlsplit(record["origin"])
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            fail("GitLab exchange project record origin is invalid")
        return ProjectRecord(
            origin=f"https://{parsed.netloc}",
            project_id=int(record["project_id"]),
            project_path=record["project_path"],
            source=source,
        )
    except Exception:
        source.close()
        raise


@dataclass(frozen=True)
class InventoryRecord:
    service: str
    target: str
    inventory_sha256: str
    common_name: str
    dns_sans: list[str]
    ip_sans: list[str]
    source: PinnedAbsoluteFile


def load_inventory_record(path: Path, uid: int) -> InventoryRecord:
    source = PinnedAbsoluteFile.open(
        path,
        owners=(uid,),
        modes=(0o400, 0o600),
        maximum=16384,
        label="PKI request inventory record",
    )
    try:
        data = source.data
        if not data.endswith(b"\n") or b"\r" in data or b"\x00" in data:
            fail("PKI request inventory record is not canonical LF-terminated text")
        try:
            lines = data.decode("ascii").splitlines()
        except UnicodeDecodeError:
            fail("PKI request inventory record is not ASCII")
        if len(lines) < len(INVENTORY_FIXED_FIELDS) + 1:
            fail("PKI request inventory record is incomplete")
        fixed: dict[str, str] = {}
        for expected, line in zip(
            INVENTORY_FIXED_FIELDS,
            lines[: len(INVENTORY_FIXED_FIELDS)],
            strict=True,
        ):
            if "=" not in line:
                fail("PKI request inventory record contains a malformed field")
            key, value = line.split("=", 1)
            if key != expected or not value:
                fail("PKI request inventory record contains an unexpected field")
            fixed[key] = value
        if fixed["schema"] != "1" or fixed["kind"] != "pki-request-inventory":
            fail("PKI request inventory record schema is unsupported")
        if not SERVICE.fullmatch(fixed["service"]):
            fail("PKI request inventory service is invalid")
        if not PRINCIPAL.fullmatch(fixed["target"]):
            fail("PKI request inventory target is invalid")
        if not HEX_64.fullmatch(fixed["inventory_sha256"]):
            fail("PKI request inventory digest is invalid")
        validate_dns(fixed["common_name"], "inventory common name")
        if not re.fullmatch(r"[1-9][0-9]*", fixed["dns_san_count"]):
            fail("PKI request inventory DNS SAN count is invalid")
        dns_count = int(fixed["dns_san_count"])
        offset = len(INVENTORY_FIXED_FIELDS)
        if dns_count > 100 or len(lines) <= offset + dns_count:
            fail("PKI request inventory DNS SAN list is incomplete")
        dns_sans: list[str] = []
        for line in lines[offset : offset + dns_count]:
            if not line.startswith("dns_san=") or not line.removeprefix("dns_san="):
                fail("PKI request inventory DNS SAN field is invalid")
            value = line.removeprefix("dns_san=")
            validate_dns(value, "inventory DNS SAN")
            dns_sans.append(value)
        offset += dns_count
        if offset >= len(lines) or not lines[offset].startswith("ip_san_count="):
            fail("PKI request inventory IP SAN count is missing")
        ip_count_value = lines[offset].removeprefix("ip_san_count=")
        if not re.fullmatch(r"0|[1-9][0-9]*", ip_count_value):
            fail("PKI request inventory IP SAN count is invalid")
        ip_count = int(ip_count_value)
        offset += 1
        if ip_count > 100 or len(lines) != offset + ip_count:
            fail("PKI request inventory IP SAN list has the wrong length")
        ip_sans: list[str] = []
        for line in lines[offset:]:
            if not line.startswith("ip_san=") or not line.removeprefix("ip_san="):
                fail("PKI request inventory IP SAN field is invalid")
            value = line.removeprefix("ip_san=")
            validate_ipv4(value, "inventory IP SAN")
            ip_sans.append(value)
        if len(set(dns_sans)) != len(dns_sans) or len(set(ip_sans)) != len(ip_sans):
            fail("PKI request inventory SAN values are repeated")
        return InventoryRecord(
            service=fixed["service"],
            target=fixed["target"],
            inventory_sha256=fixed["inventory_sha256"],
            common_name=fixed["common_name"],
            dns_sans=dns_sans,
            ip_sans=ip_sans,
            source=source,
        )
    except Exception:
        source.close()
        raise


def verify_ssh_signature(
    request: bytes,
    signature: bytes,
    allowed_signers: bytes,
    principal: str,
) -> None:
    validate_ssh_signature_container(signature)
    if not hasattr(os, "memfd_create"):
        fail("Linux memfd support is required for signature verification")
    trust_fd = os.memfd_create("pki-requesters", flags=0)
    signature_fd = os.memfd_create("pki-request-signature", flags=0)
    try:
        os.write(trust_fd, allowed_signers)
        os.write(signature_fd, signature)
        os.lseek(trust_fd, 0, os.SEEK_SET)
        os.lseek(signature_fd, 0, os.SEEK_SET)
        try:
            result = subprocess.run(
                [
                    "ssh-keygen",
                    "-Y",
                    "verify",
                    "-f",
                    f"/proc/self/fd/{trust_fd}",
                    "-I",
                    principal,
                    "-n",
                    "platform-pki-csr-request-v1",
                    "-s",
                    f"/proc/self/fd/{signature_fd}",
                ],
                input=request,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                pass_fds=(trust_fd, signature_fd),
                check=False,
                timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired):
            fail("request signature verification could not be executed")
        if result.returncode != 0:
            fail("request signature verification failed")
    finally:
        os.close(signature_fd)
        os.close(trust_fd)


@dataclass
class PinnedBytes:
    data: bytes

    def recheck(self) -> None:
        return

    def close(self) -> None:
        return


@dataclass
class RequestPackage:
    service: str
    target: str
    request_id: str
    package_name: str
    package_version: str
    expires_epoch: int | None
    files: dict[str, PinnedFile | PinnedBytes]
    trust_files: dict[str, PinnedFile]
    directories: list[PinnedDirectory]
    stage: str = "request"

    @property
    def spec(self) -> StageSpec:
        return STAGE_SPECS[self.stage]

    @property
    def package_files(self) -> tuple[str, ...]:
        return self.spec.package_files

    def recheck(self) -> None:
        if self.expires_epoch is not None and int(time.time()) > self.expires_epoch:
            fail("request expired during package publication")
        for directory in self.directories:
            directory.recheck()
        for source in (*self.files.values(), *self.trust_files.values()):
            source.recheck()

    def close(self) -> None:
        for source in (*self.files.values(), *self.trust_files.values()):
            source.close()
        for directory in reversed(self.directories):
            directory.close()


def build_manifest(
    spec: StageSpec,
    *,
    service: str,
    request_id: str,
    package_version: str,
    payloads: dict[str, bytes],
) -> bytes:
    lines = (
        "schema=1",
        "kind=pki-exchange-stage",
        f"stage={spec.name}",
        f"service={service}",
        f"request_id={request_id}",
        f"package_version={package_version}",
        f"payload_count={len(spec.payloads)}",
        *(
            f"payload={name} sha256={sha256(payloads[name])}"
            for name in spec.payloads
        ),
    )
    return ("\n".join(lines) + "\n").encode("ascii")


def validate_manifest(
    data: bytes,
    *,
    spec: StageSpec,
    service: str,
    request_id: str,
    package_version: str,
    payloads: dict[str, bytes],
) -> None:
    if not data.endswith(b"\n") or b"\r" in data or b"\x00" in data:
        fail("stage-manifest is not canonical LF-terminated text")
    try:
        lines = data.decode("ascii").splitlines()
    except UnicodeDecodeError:
        fail("stage-manifest is not printable ASCII")
    if len(lines) != len(MANIFEST_FIELDS) + len(spec.payloads):
        fail("stage-manifest has an unexpected field count")
    values: dict[str, str] = {}
    for expected, line in zip(MANIFEST_FIELDS, lines, strict=False):
        if "=" not in line:
            fail("stage-manifest contains a malformed field")
        key, value = line.split("=", 1)
        if key != expected or not value:
            fail("stage-manifest contains an unexpected field")
        values[key] = value
    expected_values = {
        "schema": "1",
        "kind": "pki-exchange-stage",
        "stage": spec.name,
        "service": service,
        "request_id": request_id,
        "package_version": package_version,
        "payload_count": str(len(spec.payloads)),
    }
    if values != expected_values:
        fail(f"stage-manifest does not bind the exact {spec.name} package")
    payload_lines = lines[len(MANIFEST_FIELDS) :]
    for name, line in zip(spec.payloads, payload_lines, strict=True):
        expected = f"payload={name} sha256={sha256(payloads[name])}"
        if line != expected:
            fail("stage-manifest payload order or digest is invalid")


def require_digest(record: dict[str, str], field: str, label: str) -> None:
    if not HEX_64.fullmatch(record[field]):
        fail(f"{label} {field} is not a lowercase SHA-256 digest")


def require_coordinate(
    record: dict[str, str],
    *,
    service: str,
    target: str,
    request_id: str,
    label: str,
) -> None:
    if record.get("schema") != "1":
        fail(f"{label} schema is unsupported")
    if (
        record.get("service") != service
        or record.get("target") != target
        or record.get("request_id") != request_id
    ):
        fail(f"{label} does not bind the selected package coordinate")
    if record.get("operation") not in {"issue", "migrate", "renew"}:
        fail(f"{label} operation is invalid")


def validate_certificate_bundle(
    data: bytes, label: str, expected_count: int
) -> tuple[bytes, ...]:
    begin = b"-----BEGIN CERTIFICATE-----\n"
    end = b"-----END CERTIFICATE-----\n"
    if not data or not data.endswith(b"\n") or b"\r" in data or b"\x00" in data:
        fail(f"{label} is not canonical PEM certificate data")
    offset = 0
    certificates: list[bytes] = []
    while offset < len(data):
        if not data.startswith(begin, offset):
            fail(f"{label} contains non-certificate or trailing bytes")
        end_offset = data.find(end, offset + len(begin))
        if end_offset < 0:
            fail(f"{label} contains a truncated certificate")
        object_end = end_offset + len(end)
        decoded = decode_single_armor(
            data[offset:object_end], "CERTIFICATE", label
        )
        validate_der_sequence(decoded, label)
        certificates.append(data[offset:object_end])
        offset = object_end
    if len(certificates) != expected_count:
        fail(f"{label} does not contain exactly {expected_count} certificates")
    return tuple(certificates)


def validate_approval_payload(
    payloads: dict[str, bytes], *, service: str, target: str, request_id: str
) -> None:
    approval = parse_record(payloads["approval"], APPROVAL_FIELDS, "approval")
    require_coordinate(
        approval,
        service=service,
        target=target,
        request_id=request_id,
        label="approval",
    )
    if not HEX_64.fullmatch(approval["nonce"]):
        fail("approval nonce is invalid")
    if not PRINCIPAL.fullmatch(approval["approver_principal"]):
        fail("approval principal is invalid")
    for field in ("request_sha256", "csr_sha256", "inventory_sha256"):
        require_digest(approval, field, "approval")
    created = canonical_epoch(approval["created_epoch"], "approval created_epoch")
    expires = canonical_epoch(approval["expires_epoch"], "approval expires_epoch")
    if expires <= created or expires - created > 86400:
        fail("approval has an invalid lifetime")
    if approval["profile"] != "server-p384-sha384-v1":
        fail("approval profile is invalid")
    validate_ssh_signature_container(payloads["approval.sig"], "approval signature")


def validate_response_payload(
    payloads: dict[str, bytes], *, service: str, target: str, request_id: str
) -> None:
    response = parse_record(payloads["response"], RESPONSE_FIELDS, "response")
    artifact = parse_record(payloads["artifact"], ARTIFACT_FIELDS, "artifact")
    require_coordinate(
        response,
        service=service,
        target=target,
        request_id=request_id,
        label="response",
    )
    require_coordinate(
        artifact,
        service=service,
        target=target,
        request_id=request_id,
        label="artifact",
    )
    for field in (
        "request_sha256",
        "approval_sha256",
        "inventory_sha256",
        "csr_sha256",
        "csr_spki_sha256",
        "certificate_sha256",
        "certificate_spki_sha256",
        "chain_sha256",
    ):
        require_digest(response, field, "response")
    for field in (
        "source_response_sha256",
        "source_response_signature_sha256",
        "certificate_sha256",
        "certificate_spki_sha256",
        "chain_sha256",
        "fullchain_sha256",
    ):
        require_digest(artifact, field, "artifact")
    if not HEX_64.fullmatch(response["nonce"]):
        fail("response nonce is invalid")
    if (
        response["candidate_state"] != "pending"
        or artifact["kind"] != "certificate-export"
        or artifact["source_kind"] != "csr-response"
        or artifact["candidate_state"] != "pending"
        or artifact["deployment_state"] != "unfinalized"
    ):
        fail("response or artifact state is invalid")
    if not PRINCIPAL.fullmatch(response["response_principal"]):
        fail("response principal is invalid")
    if response["response_principal"] != artifact["response_principal"]:
        fail("artifact response principal binding failed")
    if response["csr_spki_sha256"] != response["certificate_spki_sha256"]:
        fail("response CSR and certificate SPKI binding failed")
    if not re.fullmatch(r"g[1-9][0-9]*", response["issuer_root"]):
        fail("response root generation is invalid")
    if not re.fullmatch(
        re.escape(response["issuer_root"]) + r"-i[1-9][0-9]*",
        response["issuer_intermediate"],
    ):
        fail("response intermediate generation is invalid")
    if not re.fullmatch(r"(?:[0-9A-F]{2})+", response["serial"]):
        fail("response serial is invalid")
    not_before = canonical_epoch(response["not_before_epoch"], "response not_before")
    not_after = canonical_epoch(response["not_after_epoch"], "response not_after")
    canonical_epoch(response["created_epoch"], "response created_epoch")
    if not_after <= not_before:
        fail("response certificate lifetime is invalid")
    validate_certificate_bundle(payloads["tls.crt"], "leaf certificate", 1)
    intermediate, _root = validate_certificate_bundle(
        payloads["ca-chain.crt"], "CA chain", 2
    )
    validate_certificate_bundle(payloads["fullchain.crt"], "full chain", 2)
    certificate_public = run_checked(
        ["openssl", "x509", "-pubkey", "-noout"],
        stdin=payloads["tls.crt"],
        label="leaf certificate public-key extraction",
    )
    certificate_spki = run_checked(
        ["openssl", "pkey", "-pubin", "-outform", "DER"],
        stdin=certificate_public,
        label="leaf certificate SPKI conversion",
    )
    if sha256(certificate_spki) != response["certificate_spki_sha256"]:
        fail("leaf certificate SPKI digest differs from the response")
    if payloads["fullchain.crt"] != payloads["tls.crt"] + intermediate:
        fail("full chain does not equal the exact leaf and intermediate bytes")
    expected = {
        "source_response_sha256": sha256(payloads["response"]),
        "source_response_signature_sha256": sha256(payloads["response.sig"]),
        "certificate_sha256": sha256(payloads["tls.crt"]),
        "chain_sha256": sha256(payloads["ca-chain.crt"]),
        "fullchain_sha256": sha256(payloads["fullchain.crt"]),
    }
    if any(artifact[field] != value for field, value in expected.items()):
        fail("artifact does not bind the exact response package files")
    for field in (
        "operation",
        "certificate_sha256",
        "certificate_spki_sha256",
        "chain_sha256",
        "issuer_root",
        "issuer_intermediate",
        "serial",
        "not_before_epoch",
        "not_after_epoch",
        "created_epoch",
    ):
        if artifact[field] != response[field]:
            fail(f"artifact does not bind response field {field}")
    validate_ssh_signature_container(payloads["response.sig"], "response signature")


def validate_deployment_record(
    data: bytes, *, service: str, target: str, request_id: str
) -> dict[str, str]:
    deployment = parse_record(data, DEPLOYMENT_FIELDS, "deployment")
    require_coordinate(
        deployment,
        service=service,
        target=target,
        request_id=request_id,
        label="deployment",
    )
    if deployment["artifact_request_id"] != request_id:
        fail("deployment artifact request ID binding failed")
    for field in (
        "request_sha256",
        "response_sha256",
        "response_signature_sha256",
        "candidate_sha256",
        "artifact_manifest_sha256",
        "certificate_sha256",
        "certificate_spki_sha256",
        "chain_sha256",
        "fullchain_sha256",
        "validation_boundary_sha256",
    ):
        require_digest(deployment, field, "deployment")
    for field in (
        "local_certificate_sha256",
        "local_key_spki_sha256",
        "served_certificate_sha256",
        "served_intermediate_sha256",
    ):
        if deployment[field] != "none":
            require_digest(deployment, field, "deployment")
    if deployment["action"] not in {"finalize", "abandon"}:
        fail("deployment action is invalid")
    if deployment["result"] not in {"activated", "not-activated", "rolled-back"}:
        fail("deployment result is invalid")
    if deployment["local_key_certificate_match"] not in {"true", "false"}:
        fail("deployment key match result is invalid")
    if deployment["validation_result"] not in {"passed", "not-run"}:
        fail("deployment validation result is invalid")
    if not PRINCIPAL.fullmatch(deployment["deployment_principal"]):
        fail("deployment principal is invalid")
    canonical_epoch(deployment["created_epoch"], "deployment created_epoch")
    canonical_epoch(deployment["expires_epoch"], "deployment expires_epoch")
    return deployment


def validate_evidence_payload(
    payloads: dict[str, bytes], *, service: str, target: str, request_id: str
) -> None:
    deployment = validate_deployment_record(
        payloads["deployment"], service=service, target=target, request_id=request_id
    )
    boundary = parse_record(
        payloads["validation-boundary"],
        VALIDATION_BOUNDARY_FIELDS,
        "validation-boundary",
    )
    result = parse_record(
        payloads["validation-result"], VALIDATION_RESULT_FIELDS, "validation-result"
    )
    if (
        boundary["schema"] != "1"
        or boundary["kind"] != "pki-validation-boundary"
        or boundary["service"] != service
        or boundary["target"] != target
    ):
        fail("validation-boundary does not bind the selected coordinate")
    if (
        result["schema"] != "1"
        or result["kind"] != "pki-validation-result"
        or result["service"] != service
        or result["target"] != target
        or result["request_id"] != request_id
    ):
        fail("validation-result does not bind the selected coordinate")
    if sha256(payloads["validation-boundary"]) != deployment["validation_boundary_sha256"]:
        fail("deployment does not bind the exact validation-boundary")
    expected = {
        "artifact_manifest_sha256": deployment["artifact_manifest_sha256"],
        "validation_boundary_sha256": deployment["validation_boundary_sha256"],
        "action": deployment["action"],
        "result": deployment["result"],
        "local_validator": boundary["local_validator"],
        "remote_validator": boundary["remote_validator"],
        "endpoint": boundary["endpoint"],
        "served_certificate_sha256": deployment["served_certificate_sha256"],
        "served_intermediate_sha256": deployment["served_intermediate_sha256"],
        "activation_epoch": deployment["activation_epoch"],
        "validation_epoch": deployment["validation_epoch"],
        "deployment_sha256": sha256(payloads["deployment"]),
    }
    if any(result[field] != value for field, value in expected.items()):
        fail("validation-result does not cross-bind the exact deployment and boundary")
    validate_ssh_signature_container(payloads["deployment.sig"], "deployment signature")
    validate_ssh_signature_container(
        payloads["validation-result.sig"], "validation-result signature"
    )


def validate_outcome_payload(
    payloads: dict[str, bytes], *, service: str, target: str, request_id: str
) -> None:
    outcome = parse_record(payloads["outcome"], OUTCOME_FIELDS, "outcome")
    deployment = validate_deployment_record(
        payloads["deployment"], service=service, target=target, request_id=request_id
    )
    decision = parse_record(payloads["decision"], DECISION_FIELDS, "decision")
    require_coordinate(
        outcome,
        service=service,
        target=target,
        request_id=request_id,
        label="outcome",
    )
    require_coordinate(
        decision,
        service=service,
        target=target,
        request_id=request_id,
        label="decision",
    )
    if outcome["kind"] != "csr-signer-outcome":
        fail("outcome kind is invalid")
    for record, label in ((outcome, "outcome"), (decision, "decision")):
        for field in (
            "request_sha256",
            "response_sha256",
            "response_signature_sha256",
            "candidate_sha256",
            "artifact_manifest_sha256",
            "certificate_sha256",
            "certificate_spki_sha256",
            "chain_sha256",
            "fullchain_sha256",
            "deployment_sha256",
            "deployment_signature_sha256",
            "deployers_sha256",
        ):
            require_digest(record, field, label)
    require_digest(outcome, "decision_sha256", "outcome")
    if outcome["action"] not in {"finalize", "abandon"}:
        fail("outcome action is invalid")
    expected_state = "finalized" if outcome["action"] == "finalize" else "abandoned"
    if outcome["state"] != expected_state or decision["state"] != expected_state:
        fail("outcome terminal state is invalid")
    if not PRINCIPAL.fullmatch(outcome["outcome_principal"]):
        fail("outcome principal is invalid")
    canonical_epoch(outcome["created_epoch"], "outcome created_epoch")
    expected_digests = {
        "deployment_sha256": sha256(payloads["deployment"]),
        "deployment_signature_sha256": sha256(payloads["deployment.sig"]),
        "deployers_sha256": sha256(payloads["deployers.allowed_signers"]),
        "decision_sha256": sha256(payloads["decision"]),
    }
    if any(outcome[field] != value for field, value in expected_digests.items()):
        fail("outcome does not bind the exact terminal package files")
    if decision["deployment_sha256"] != expected_digests["deployment_sha256"]:
        fail("decision does not bind the exact deployment")
    if decision["deployment_signature_sha256"] != expected_digests["deployment_signature_sha256"]:
        fail("decision does not bind the exact deployment signature")
    if decision["deployers_sha256"] != expected_digests["deployers_sha256"]:
        fail("decision does not bind the exact deployer trust")
    for field in (
        "operation",
        "request_sha256",
        "response_sha256",
        "response_signature_sha256",
        "candidate_sha256",
        "artifact_manifest_sha256",
        "certificate_sha256",
        "certificate_spki_sha256",
        "chain_sha256",
        "fullchain_sha256",
        "deployment_sha256",
        "deployment_signature_sha256",
        "deployers_sha256",
        "action",
        "state",
        "resulting_active_request_id",
        "created_epoch",
    ):
        if outcome[field] != decision[field]:
            fail(f"outcome does not bind decision field {field}")
    for field in (
        "request_sha256",
        "response_sha256",
        "response_signature_sha256",
        "candidate_sha256",
        "artifact_manifest_sha256",
        "certificate_sha256",
        "certificate_spki_sha256",
        "chain_sha256",
        "fullchain_sha256",
        "action",
    ):
        if decision[field] != deployment[field]:
            fail(f"decision does not bind deployment field {field}")
    deployers = parse_allowed_signers(
        payloads["deployers.allowed_signers"], "deployer trust"
    )
    if deployment["deployment_principal"] not in deployers:
        fail("outcome deployer trust omits the deployment principal")
    validate_ssh_signature_container(payloads["deployment.sig"], "deployment signature")
    validate_ssh_signature_container(payloads["outcome.sig"], "outcome signature")


def validate_nonrequest_payload(
    spec: StageSpec,
    payloads: dict[str, bytes],
    *,
    service: str,
    target: str,
    request_id: str,
) -> None:
    validators = {
        "approval": validate_approval_payload,
        "response": validate_response_payload,
        "evidence": validate_evidence_payload,
        "outcome": validate_outcome_payload,
    }
    validator = validators.get(spec.name)
    if validator is None:
        fail("request package requires request-specific validation inputs")
    validator(payloads, service=service, target=target, request_id=request_id)


def validate_request_payload(
    payloads: dict[str, bytes],
    trust_data: dict[str, bytes],
    *,
    service: str,
    target: str,
    request_id: str,
    inventory: InventoryRecord,
    transport_host_key_sha256: str,
) -> int:
    request = parse_record(payloads["request"], REQUEST_FIELDS, "request")
    receipt = parse_record(
        payloads["collection-receipt"], RECEIPT_FIELDS, "collection-receipt"
    )
    policy = parse_record(trust_data["policy"], POLICY_FIELDS, "policy")
    if request["schema"] != "1":
        fail("request schema is not supported")
    if (
        request["request_id"] != request_id
        or request["service"] != service
        or request["target"] != target
        or request["requester_principal"] != target
        or request["inventory_sha256"] != inventory.inventory_sha256
        or request["profile"] != "server-p384-sha384-v1"
    ):
        fail("request does not bind the selected package identity")
    if request["operation"] not in {"issue", "migrate", "renew"}:
        fail("request operation is invalid")
    if not HEX_64.fullmatch(request["nonce"]):
        fail("request nonce is invalid")
    if not PRINCIPAL.fullmatch(request["response_principal"]):
        fail("request response principal is invalid")
    for field in ("inventory_sha256", "csr_sha256", "csr_spki_sha256"):
        if not HEX_64.fullmatch(request[field]):
            fail(f"request {field} is invalid")
    if request["current_cert_sha256"] != "none" and not HEX_64.fullmatch(
        request["current_cert_sha256"]
    ):
        fail("request current certificate digest is invalid")
    if (
        request["operation"] == "issue"
        and request["current_cert_sha256"] != "none"
    ) or (
        request["operation"] in {"migrate", "renew"}
        and request["current_cert_sha256"] == "none"
    ):
        fail("request operation and current certificate binding conflict")
    created = canonical_epoch(request["created_epoch"], "request created_epoch")
    expires = canonical_epoch(request["expires_epoch"], "request expires_epoch")
    now = int(time.time())
    if expires <= created or expires - created > 604800 or now > expires:
        fail("request is expired or has an invalid lifetime")

    validate_frozen_trust(
        policy,
        trust_data,
        target=target,
        response_principal=request["response_principal"],
    )
    request_max_age = canonical_epoch(
        policy["request_max_age_seconds"], "policy request maximum age"
    )
    clock_skew = canonical_epoch(policy["clock_skew_seconds"], "policy clock skew")
    if request_max_age > 604800 or expires - created > request_max_age:
        fail("request exceeds the frozen trust policy lifetime")
    if created > now + clock_skew:
        fail("request creation time is in the future")
    if policy["response_principal"] != request["response_principal"]:
        fail("request response principal differs from frozen policy")

    csr = payloads["tls.csr"]
    if sha256(csr) != request["csr_sha256"]:
        fail("CSR digest differs from the request")
    csr_spki = validate_csr_profile(
        csr,
        common_name=inventory.common_name,
        dns_sans=inventory.dns_sans,
        ip_sans=inventory.ip_sans,
    )
    if sha256(csr_spki) != request["csr_spki_sha256"]:
        fail("CSR public-key digest differs from the request")
    verify_ssh_signature(
        payloads["request"],
        payloads["request.sig"],
        trust_data["requesters.allowed_signers"],
        target,
    )

    trust_digests = {name: sha256(data) for name, data in trust_data.items()}
    expected_receipt = {
        "schema": "1",
        "kind": "pki-request-collection",
        "service": service,
        "target": target,
        "request_id": request_id,
        "transport": "ssh",
        "transport_host_key_sha256": transport_host_key_sha256,
        "csr_sha256": sha256(csr),
        "request_sha256": sha256(payloads["request"]),
        "request_signature_sha256": sha256(payloads["request.sig"]),
        "trust_policy_sha256": trust_digests["policy"],
        "request_trust_sha256": trust_digests["requesters.allowed_signers"],
        "approval_trust_sha256": trust_digests["approvers.allowed_signers"],
        "response_trust_sha256": trust_digests["responses.allowed_signers"],
        "deployment_trust_sha256": trust_digests["deployers.allowed_signers"],
        "request_principal": target,
        "request_namespace": "platform-pki-csr-request-v1",
        "verification_result": "passed",
    }
    if any(receipt[key] != value for key, value in expected_receipt.items()):
        fail("collection-receipt does not bind the exact request and trust")
    collected = canonical_epoch(receipt["collected_epoch"], "collected_epoch")
    if collected < created or collected > now + clock_skew or collected > expires:
        fail("collection receipt time is outside the request lifetime")
    return expires


def load_request_package(
    args: SimpleNamespace, inventory: InventoryRecord
) -> RequestPackage:
    uid = os.geteuid()
    exchange_root = Path(args.exchange_root)
    if not exchange_root.is_absolute() or exchange_root == Path("/"):
        fail("exchange root must be a non-root absolute path")
    try:
        resolved_root = exchange_root.resolve(strict=True)
    except OSError as error:
        fail(f"cannot resolve exchange root: {error.strerror}")
    if resolved_root != exchange_root:
        fail("exchange root must not contain symlinks")
    if _inside_public_repository(exchange_root):
        fail("exchange root must be outside the public repository")

    request_id = args.request_id
    service = args.service
    target = args.target
    if service != inventory.service or target != inventory.target:
        fail("selected service or target differs from protected inventory")
    directories: list[PinnedDirectory] = []
    files: dict[str, PinnedFile] = {}
    trust_files: dict[str, PinnedFile] = {}
    try:
        root_directory = PinnedDirectory.open(exchange_root, owner=uid)
        directories.append(root_directory)
        service_directory = PinnedDirectory.open_child(
            root_directory, service, owner=uid
        )
        directories.append(service_directory)
        request_parent = PinnedDirectory.open_child(
            service_directory, request_id, owner=uid
        )
        directories.append(request_parent)
        request_dir = PinnedDirectory.open_child(
            request_parent, "request", owner=uid
        )
        directories.append(request_dir)
        trust_dir = PinnedDirectory.open_child(request_parent, "trust", owner=uid)
        directories.append(trust_dir)
        if request_dir.names() != set(PACKAGE_FILES):
            fail("request package directory does not contain the exact five files")
        if trust_dir.names() != set(TRUST_NAMES):
            fail("controller trust directory does not contain the exact five files")
        for name in PACKAGE_FILES:
            files[name] = PinnedFile.open(
                request_dir,
                name,
                owner=uid,
                maximum=MAX_FILE_SIZE[name],
            )
        for name in TRUST_NAMES:
            trust_files[name] = PinnedFile.open(
                trust_dir,
                name,
                owner=uid,
                maximum=65536,
            )

        trust_data = {name: source.data for name, source in trust_files.items()}
        payloads = {name: files[name].data for name in REQUEST_FILES}
        expires = validate_request_payload(
            payloads,
            trust_data,
            service=service,
            target=target,
            request_id=request_id,
            inventory=inventory,
            transport_host_key_sha256=args.transport_host_key_sha256,
        )
        validate_manifest(
            files["stage-manifest"].data,
            spec=STAGE_SPECS["request"],
            service=service,
            request_id=request_id,
            package_version=request_id,
            payloads=payloads,
        )
        for source in trust_files.values():
            source.recheck()
        for directory in directories:
            directory.recheck()
        return RequestPackage(
            service=service,
            target=target,
            request_id=request_id,
            package_name=f"pki-exchange-request-{service}",
            package_version=request_id,
            expires_epoch=expires,
            files=files,
            trust_files=trust_files,
            directories=directories,
        )
    except Exception:
        for source in (*files.values(), *trust_files.values()):
            try:
                source.close()
            except OSError:
                pass
        for directory in reversed(directories):
            try:
                directory.close()
            except OSError:
                pass
        raise


def require_canonical_external_directory(path: Path, label: str) -> None:
    if not path.is_absolute() or path == Path("/"):
        fail(f"{label} must be a non-root absolute path")
    if _inside_public_repository(path):
        fail(f"{label} must be outside the public repository")
    try:
        if path.resolve(strict=True) != path:
            fail(f"{label} must not contain symlinks")
    except OSError as error:
        fail(f"cannot resolve {label}: {error.strerror}")


@dataclass
class RequestValidationContext:
    inventory: InventoryRecord
    trust_directory: PinnedDirectory
    trust_files: dict[str, PinnedFile]

    @property
    def trust_data(self) -> dict[str, bytes]:
        return {name: source.data for name, source in self.trust_files.items()}

    def recheck(self) -> None:
        self.inventory.source.recheck()
        self.trust_directory.recheck()
        for source in self.trust_files.values():
            source.recheck()

    def close(self) -> None:
        for source in self.trust_files.values():
            source.close()
        self.trust_directory.close()
        self.inventory.source.close()


def load_request_context(args: SimpleNamespace, uid: int) -> RequestValidationContext:
    inventory = load_inventory_record(Path(args.inventory_record), uid)
    trust_directory: PinnedDirectory | None = None
    trust_files: dict[str, PinnedFile] = {}
    try:
        trust_path = Path(args.trust_dir)
        require_canonical_external_directory(trust_path, "request trust directory")
        trust_directory = PinnedDirectory.open(trust_path, owner=uid)
        if trust_directory.names() != set(TRUST_NAMES):
            fail("request trust directory does not contain the exact five files")
        for name in TRUST_NAMES:
            trust_files[name] = PinnedFile.open(
                trust_directory, name, owner=uid, maximum=65536
            )
        return RequestValidationContext(inventory, trust_directory, trust_files)
    except Exception:
        for source in trust_files.values():
            try:
                source.close()
            except OSError:
                pass
        if trust_directory is not None:
            trust_directory.close()
        inventory.source.close()
        raise


def load_generic_source(
    args: SimpleNamespace,
    spec: StageSpec,
    request_context: RequestValidationContext | None,
) -> RequestPackage:
    uid = os.geteuid()
    source_path = Path(args.source_dir)
    require_canonical_external_directory(source_path, "source directory")
    directory = PinnedDirectory.open(source_path, owner=uid)
    files: dict[str, PinnedFile | PinnedBytes] = {}
    try:
        if directory.names() != set(spec.payloads):
            fail(
                f"{spec.name} source directory does not contain the exact "
                f"{len(spec.payloads)} payload files"
            )
        for name in spec.payloads:
            files[name] = PinnedFile.open(
                directory,
                name,
                owner=uid,
                maximum=MAX_FILE_SIZE[name],
            )
        payloads = {name: files[name].data for name in spec.payloads}
        expected_version = spec.package_version(args.request_id, payloads)
        if args.package_version != expected_version:
            fail(f"package version does not bind the exact {spec.name} payload")
        expires: int | None = None
        if spec.name == "request":
            if request_context is None:
                fail("request package validation context is missing")
            expires = validate_request_payload(
                payloads,
                request_context.trust_data,
                service=args.service,
                target=args.target,
                request_id=args.request_id,
                inventory=request_context.inventory,
                transport_host_key_sha256=args.transport_host_key_sha256,
            )
        else:
            validate_nonrequest_payload(
                spec,
                payloads,
                service=args.service,
                target=args.target,
                request_id=args.request_id,
            )
        manifest = build_manifest(
            spec,
            service=args.service,
            request_id=args.request_id,
            package_version=args.package_version,
            payloads=payloads,
        )
        validate_manifest(
            manifest,
            spec=spec,
            service=args.service,
            request_id=args.request_id,
            package_version=args.package_version,
            payloads=payloads,
        )
        files["stage-manifest"] = PinnedBytes(manifest)
        directory.recheck()
        for source in files.values():
            source.recheck()
        return RequestPackage(
            service=args.service,
            target=args.target,
            request_id=args.request_id,
            package_name=spec.package_name(args.service),
            package_version=args.package_version,
            expires_epoch=expires,
            files=files,
            trust_files={},
            directories=[directory],
            stage=spec.name,
        )
    except Exception:
        for source in files.values():
            try:
                source.close()
            except OSError:
                pass
        directory.close()
        raise


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


class GitLabClient:
    def __init__(
        self,
        *,
        origin: str,
        project_id: int,
        token_header: str,
        token: str,
        ca_data: bytes,
        configuration_sources: tuple[Any, ...],
        timeout: int,
    ) -> None:
        parsed = urllib.parse.urlsplit(origin)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            fail("GitLab origin must be one HTTPS origin without credentials or a path")
        self.origin = f"https://{parsed.netloc}"
        self.project_id = project_id
        self.project_path_endpoint = f"/api/v4/projects/{project_id}"
        self.base_path = f"/api/v4/projects/{project_id}/packages"
        self.token_header = token_header
        self.token = token
        self.timeout = timeout
        self.configuration_sources = configuration_sources
        try:
            context = ssl.create_default_context(cadata=ca_data.decode("ascii"))
        except (UnicodeDecodeError, ssl.SSLError):
            fail("GitLab CA file is not a valid ASCII PEM trust bundle")
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=context), NoRedirect()
        )

    def _validate_url(self, method: str, url: str) -> None:
        parsed = urllib.parse.urlsplit(url)
        if f"{parsed.scheme}://{parsed.netloc}" != self.origin:
            fail("GitLab pagination or request URL changed origin")
        if parsed.username or parsed.password or parsed.fragment:
            fail("GitLab request URL is outside the package endpoint allowlist")
        package_files = re.fullmatch(
            re.escape(self.base_path) + r"/[1-9][0-9]*/package_files",
            parsed.path,
        )
        generic_file = re.fullmatch(
            re.escape(self.base_path) + r"/generic/[^/]+/[^/]+/[^/]+",
            parsed.path,
        )
        if (
            method == "GET"
            and parsed.path not in {self.project_path_endpoint, self.base_path}
            and not package_files
            and not generic_file
        ):
            fail("GitLab GET URL is outside the package endpoint allowlist")
        if method == "GET" and generic_file and parsed.query:
            fail("GitLab GET URL is outside the package endpoint allowlist")
        if method == "PUT" and (not generic_file or parsed.query):
            fail("GitLab PUT URL is outside the package endpoint allowlist")

    def request(
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        maximum: int = 2 * 1024 * 1024,
    ) -> tuple[bytes, Any]:
        if method not in {"GET", "PUT"}:
            fail("GitLab request method is not allowlisted")
        self._validate_url(method, url)
        headers = {
            self.token_header: self.token,
            "Accept": "application/json" if method == "GET" else "*/*",
        }
        if data is not None:
            headers["Content-Type"] = "application/octet-stream"
        for source in self.configuration_sources:
            source.recheck()
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        transport_error: str | None = None
        body = b""
        status = 0
        response_headers: Any = {}
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                body = response.read(maximum + 1)
                status = response.status
                response_headers = response.headers
        except urllib.error.HTTPError as error:
            transport_error = (
                f"GitLab returned HTTP {error.code} for an allowlisted {method} request"
            )
        except (urllib.error.URLError, TimeoutError, OSError):
            transport_error = f"GitLab {method} request failed without a definitive result"
        finally:
            for source in self.configuration_sources:
                source.recheck()
        if transport_error is not None:
            fail(transport_error)
        if len(body) > maximum:
            fail("GitLab response exceeds the configured size limit")
        if method == "GET" and status != 200:
            fail(f"GitLab GET returned unexpected HTTP {status}")
        if method == "PUT" and status != 201:
            fail(f"GitLab upload returned unexpected HTTP {status}")
        return body, response_headers

    def verify_project(self, expected_path: str) -> None:
        body, _ = self.request(
            "GET", f"{self.origin}{self.project_path_endpoint}"
        )
        try:
            value = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            fail("GitLab project endpoint returned malformed JSON")
        if not isinstance(value, dict):
            fail("GitLab project endpoint returned a non-object")
        expected_web_url = f"{self.origin}/{expected_path}"
        if (
            type(value.get("id")) is not int
            or value.get("id") != self.project_id
            or value.get("path_with_namespace") != expected_path
            or value.get("web_url") != expected_web_url
        ):
            fail("GitLab project metadata differs from the protected project record")

    def get_pages(self, path: str, query: dict[str, str]) -> list[Any]:
        encoded = urllib.parse.urlencode(query)
        url = f"{self.origin}{path}?{encoded}"
        pages: list[Any] = []
        seen: set[str] = set()
        expected_page = 1
        for _ in range(100):
            if url in seen:
                fail("GitLab pagination loop detected")
            seen.add(url)
            parsed = urllib.parse.urlsplit(url)
            try:
                actual_query = urllib.parse.parse_qs(
                    parsed.query,
                    keep_blank_values=True,
                    strict_parsing=True,
                )
            except ValueError:
                fail("GitLab pagination query is malformed")
            expected_query = {key: [value] for key, value in query.items()}
            expected_query["page"] = [str(expected_page)]
            if parsed.path != path or actual_query != expected_query:
                fail("GitLab pagination changed the exact endpoint query")
            body, headers = self.request("GET", url)
            try:
                value = json.loads(body)
            except (UnicodeDecodeError, json.JSONDecodeError):
                fail("GitLab returned malformed JSON")
            if not isinstance(value, list):
                fail("GitLab list endpoint returned a non-list response")
            pages.extend(value)
            next_url = self._next_link(headers.get("Link"))
            if next_url is None:
                return pages
            self._validate_url("GET", next_url)
            expected_page += 1
            url = next_url
        fail("GitLab pagination exceeded 100 pages")

    @staticmethod
    def _next_link(value: str | None) -> str | None:
        if not value:
            return None
        next_links: list[str] = []
        for part in value.split(","):
            match = re.fullmatch(r'\s*<([^>]+)>;\s*rel="([^"]+)"\s*', part)
            if not match:
                fail("GitLab returned a malformed pagination Link header")
            if match.group(2) == "next":
                next_links.append(match.group(1))
        if len(next_links) > 1:
            fail("GitLab returned multiple next-page links")
        return next_links[0] if next_links else None

    def packages(self, name: str, version: str) -> list[dict[str, Any]]:
        matches: list[dict[str, Any]] = []
        for status_name in STATUSES:
            values = self.get_pages(
                self.base_path,
                {
                    "package_type": "generic",
                    "package_name": name,
                    "package_version": version,
                    "status": status_name,
                    "per_page": "100",
                    "page": "1",
                },
            )
            for value in values:
                if not isinstance(value, dict):
                    fail("GitLab package listing contains a non-object")
                if value.get("name") == name and value.get("version") == version:
                    if value.get("package_type") != "generic":
                        fail("exact GitLab coordinate has the wrong package type")
                    if value.get("status") not in STATUSES:
                        fail("exact GitLab coordinate has an unknown status")
                    if value.get("status") != status_name:
                        fail("GitLab package status differs from its status query")
                    if type(value.get("id")) is not int or value["id"] <= 0:
                        fail("GitLab package object has an invalid ID")
                    matches.append(value)
        return matches

    def package_files(self, package_id: int) -> list[dict[str, Any]]:
        values = self.get_pages(
            f"{self.base_path}/{package_id}/package_files",
            {"per_page": "100", "page": "1", "order_by": "file_name", "sort": "asc"},
        )
        result: list[dict[str, Any]] = []
        for value in values:
            if not isinstance(value, dict):
                fail("GitLab package-file listing contains a non-object")
            if (
                type(value.get("id")) is not int
                or value["id"] <= 0
                or type(value.get("package_id")) is not int
                or value["package_id"] != package_id
            ):
                fail("GitLab package file belongs to another package")
            name = value.get("file_name")
            digest = value.get("file_sha256")
            if not isinstance(name, str) or not HEX_64.fullmatch(str(digest)):
                fail("GitLab package file has invalid metadata")
            result.append(value)
        return result

    def upload(self, package_name: str, version: str, name: str, data: bytes) -> None:
        components = tuple(
            urllib.parse.quote(value, safe="")
            for value in (package_name, version, name)
        )
        url = (
            f"{self.origin}{self.base_path}/generic/"
            f"{components[0]}/{components[1]}/{components[2]}"
        )
        self.request("PUT", url, data=data)

    def download(
        self, package_name: str, version: str, name: str, maximum: int
    ) -> bytes:
        components = tuple(
            urllib.parse.quote(value, safe="")
            for value in (package_name, version, name)
        )
        url = (
            f"{self.origin}{self.base_path}/generic/"
            f"{components[0]}/{components[1]}/{components[2]}"
        )
        body, _ = self.request("GET", url, maximum=maximum)
        if not body:
            fail(f"GitLab returned an empty package file: {name}")
        return body


def inspect_coordinate(
    client: GitLabClient,
    package: RequestPackage,
    *,
    processing_attempts: int,
    processing_interval: int,
) -> tuple[int | None, dict[str, str]]:
    for attempt in range(processing_attempts):
        package.recheck()
        objects = client.packages(package.package_name, package.package_version)
        if not objects:
            return None, {}
        if len(objects) != 1:
            fail("GitLab coordinate is ambiguous across package statuses")
        selected = objects[0]
        if selected["status"] == "processing":
            if attempt + 1 < processing_attempts:
                time.sleep(processing_interval)
                continue
            fail("GitLab processing status did not settle within the configured bound")
        if selected["status"] != "default":
            fail(f"GitLab coordinate is blocked in status {selected['status']}")
        package_id = selected["id"]
        listed = client.package_files(package_id)
        files: dict[str, str] = {}
        for value in listed:
            name = value["file_name"]
            if name not in package.package_files:
                fail(f"GitLab {package.stage} package contains an unexpected file")
            if name in files:
                fail(f"GitLab {package.stage} package contains a duplicate filename")
            files[name] = value["file_sha256"]
        return package_id, files
    fail("GitLab processing status did not settle within the configured bound")


@dataclass
class TransportContext:
    project: ProjectRecord
    token_source: PinnedAbsoluteFile
    ca_source: PinnedAbsoluteFile
    client: GitLabClient

    def close(self) -> None:
        self.ca_source.close()
        self.token_source.close()
        self.project.source.close()


def load_transport(
    args: SimpleNamespace,
    uid: int,
    configuration_sources: tuple[Any, ...] = (),
) -> TransportContext:
    project: ProjectRecord | None = None
    token_source: PinnedAbsoluteFile | None = None
    ca_source: PinnedAbsoluteFile | None = None
    try:
        project = load_project_record(Path(args.project_record), uid)
        token_source = PinnedAbsoluteFile.open(
            Path(args.token_file),
            owners=(uid,),
            modes=(0o400, 0o600),
            maximum=4096,
            label="GitLab token file",
        )
        try:
            token = token_source.data.decode("ascii")
        except UnicodeDecodeError:
            fail("GitLab token is not ASCII")
        if token.endswith("\n"):
            token = token[:-1]
        if not token or any(character.isspace() for character in token):
            fail("GitLab token file must contain exactly one nonempty token")
        ca_source = PinnedAbsoluteFile.open(
            Path(args.ca_file),
            owners=(0, uid),
            modes=(0o400, 0o600, 0o644),
            maximum=1024 * 1024,
            label="GitLab CA file",
        )
        header = {
            "job": "JOB-TOKEN",
            "private": "PRIVATE-TOKEN",
            "deploy": "DEPLOY-TOKEN",
        }[args.token_type]
        client = GitLabClient(
            origin=project.origin,
            project_id=project.project_id,
            token_header=header,
            token=token,
            ca_data=ca_source.data,
            configuration_sources=(
                *configuration_sources,
                project.source,
                token_source,
                ca_source,
            ),
            timeout=args.timeout,
        )
        client.verify_project(project.project_path)
        return TransportContext(project, token_source, ca_source, client)
    except Exception:
        if ca_source is not None:
            ca_source.close()
        if token_source is not None:
            token_source.close()
        if project is not None:
            project.source.close()
        raise


def publish_loaded_package(
    args: SimpleNamespace,
    package: RequestPackage,
    transport: TransportContext,
) -> dict[str, Any]:
    client = transport.client
    project = transport.project
    package_id, remote = inspect_coordinate(
        client,
        package,
        processing_attempts=args.processing_attempts,
        processing_interval=args.processing_interval,
    )
    expected = {
        name: sha256(package.files[name].data) for name in package.package_files
    }
    if not set(remote).issubset(expected):
        fail(f"GitLab {package.stage} package contains an unexpected file")
    for name, digest in remote.items():
        if digest != expected[name]:
            fail(
                f"GitLab {package.stage} package conflicts with protected local bytes"
            )
    if "stage-manifest" in remote and remote != expected:
        fail(
            f"GitLab manifest-present {package.stage} package is incomplete and unusable"
        )

    changed = False
    for name in package.package_files:
        package.recheck()
        if name not in remote:
            client.upload(
                package.package_name,
                package.package_version,
                name,
                package.files[name].data,
            )
            changed = True
            package_id, remote = inspect_coordinate(
                client,
                package,
                processing_attempts=args.processing_attempts,
                processing_interval=args.processing_interval,
            )
            if package_id is None or remote.get(name) != expected[name]:
                fail("GitLab did not publish the exact uploaded package file")
            if not set(remote).issubset(expected):
                fail(f"GitLab {package.stage} package changed during publication")
            for remote_name, digest in remote.items():
                if digest != expected[remote_name]:
                    fail(f"GitLab {package.stage} package changed during publication")
            if "stage-manifest" in remote and remote != expected:
                fail(
                    f"GitLab manifest-present {package.stage} package is incomplete "
                    "and unusable"
                )

    package.recheck()
    package_id, remote = inspect_coordinate(
        client,
        package,
        processing_attempts=args.processing_attempts,
        processing_interval=args.processing_interval,
    )
    package.recheck()
    for source in (
        transport.project.source,
        transport.token_source,
        transport.ca_source,
    ):
        source.recheck()
    if package_id is None or remote != expected:
        fail(f"GitLab {package.stage} package is not complete after publication")
    return {
        "status": "published" if changed else "existing",
        "stage": package.stage,
        "project_id": project.project_id,
        "project_path": project.project_path,
        "package_id": package_id,
        "package_name": package.package_name,
        "package_version": package.package_version,
        "file_sha256": expected,
    }


def publish_request(args: SimpleNamespace) -> dict[str, Any]:
    uid = os.geteuid()
    inventory: InventoryRecord | None = None
    package: RequestPackage | None = None
    transport: TransportContext | None = None
    try:
        inventory = load_inventory_record(Path(args.inventory_record), uid)
        package = load_request_package(args, inventory)
        transport = load_transport(
            args,
            uid,
            configuration_sources=(
                inventory.source,
                *package.trust_files.values(),
                *package.directories,
            ),
        )
        return publish_loaded_package(args, package, transport)
    finally:
        if transport is not None:
            transport.close()
        if package is not None:
            package.close()
        if inventory is not None:
            inventory.source.close()


def publish_generic(args: SimpleNamespace) -> dict[str, Any]:
    uid = os.geteuid()
    spec = STAGE_SPECS[args.stage]
    request_context: RequestValidationContext | None = None
    package: RequestPackage | None = None
    transport: TransportContext | None = None
    try:
        if spec.name == "request":
            request_context = load_request_context(args, uid)
        package = load_generic_source(args, spec, request_context)
        configuration_sources = (
            (
                request_context.inventory.source,
                request_context.trust_directory,
                *request_context.trust_files.values(),
            )
            if request_context is not None
            else ()
        )
        transport = load_transport(
            args, uid, configuration_sources=configuration_sources
        )
        result = publish_loaded_package(args, package, transport)
        if request_context is not None:
            request_context.recheck()
        return result
    finally:
        if transport is not None:
            transport.close()
        if package is not None:
            package.close()
        if request_context is not None:
            request_context.close()


def remove_stage(parent: PinnedDirectory, name: str, files: tuple[str, ...]) -> None:
    descriptor: int | None = None
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent.descriptor,
        )
        for filename in files:
            try:
                os.unlink(filename, dir_fd=descriptor)
            except FileNotFoundError:
                continue
            except OSError:
                break
    except FileNotFoundError:
        return
    except OSError:
        pass
    finally:
        if descriptor is not None:
            os.close(descriptor)
    try:
        os.rmdir(name, dir_fd=parent.descriptor)
    except OSError:
        pass


def rename_no_replace(
    parent: PinnedDirectory, source_name: str, destination_name: str
) -> bool:
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        fail("atomic no-clobber directory publication requires Linux renameat2")
    renameat2.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    renameat2.restype = ctypes.c_int
    result = renameat2(
        parent.descriptor,
        os.fsencode(source_name),
        parent.descriptor,
        os.fsencode(destination_name),
        1,
    )
    if result == 0:
        return True
    error = ctypes.get_errno()
    if error == errno.EEXIST:
        return False
    fail(f"atomic destination publication failed: {os.strerror(error)}")


def existing_destination_matches(
    parent: PinnedDirectory,
    destination_name: str,
    files: dict[str, bytes],
) -> bool:
    try:
        directory = PinnedDirectory.open_child(
            parent, destination_name, owner=os.geteuid()
        )
    except PackageError:
        raise
    opened: list[PinnedFile] = []
    try:
        if directory.names() != set(files):
            return False
        for name, expected in files.items():
            source = PinnedFile.open(
                directory,
                name,
                owner=os.geteuid(),
                maximum=MAX_FILE_SIZE[name],
            )
            opened.append(source)
            if source.data != expected:
                return False
        directory.recheck()
        for source in opened:
            source.recheck()
        return True
    finally:
        for source in opened:
            source.close()
        directory.close()


def publish_destination(destination: Path, files: dict[str, bytes]) -> str:
    uid = os.geteuid()
    if (
        not destination.is_absolute()
        or destination == Path("/")
        or destination.name in {"", ".", ".."}
    ):
        fail("destination directory must be a non-root absolute path")
    if _inside_public_repository(destination):
        fail("destination directory must be outside the public repository")
    parent_path = destination.parent
    require_canonical_external_directory(parent_path, "destination parent directory")
    parent = PinnedDirectory.open(parent_path, owner=uid)
    stage_name = f".{destination.name}.stage-{secrets.token_hex(16)}"
    stage_descriptor: int | None = None
    try:
        try:
            os.stat(destination.name, dir_fd=parent.descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            if existing_destination_matches(parent, destination.name, files):
                return "existing"
            fail("destination directory conflicts with downloaded package bytes")
        try:
            os.mkdir(stage_name, 0o700, dir_fd=parent.descriptor)
            stage_descriptor = os.open(
                stage_name,
                os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=parent.descriptor,
            )
            for name, data in files.items():
                descriptor = os.open(
                    name,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                    dir_fd=stage_descriptor,
                )
                try:
                    os.fchmod(descriptor, 0o600)
                    view = memoryview(data)
                    try:
                        while view:
                            written = os.write(descriptor, view)
                            if written <= 0:
                                fail("destination file write made no progress")
                            view = view[written:]
                    finally:
                        view.release()
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            os.fsync(stage_descriptor)
            os.close(stage_descriptor)
            stage_descriptor = None
            parent.recheck()
            if rename_no_replace(parent, stage_name, destination.name):
                os.fsync(parent.descriptor)
                return "downloaded"
            if existing_destination_matches(parent, destination.name, files):
                return "existing"
            fail("destination appeared concurrently with conflicting package bytes")
        finally:
            if stage_descriptor is not None:
                os.close(stage_descriptor)
            remove_stage(parent, stage_name, tuple(files))
    finally:
        parent.close()


def validate_downloaded_payload(
    args: SimpleNamespace,
    spec: StageSpec,
    files: dict[str, bytes],
    request_context: RequestValidationContext | None,
) -> None:
    payloads = {name: files[name] for name in spec.payloads}
    if spec.package_version(args.request_id, payloads) != args.package_version:
        fail(f"package version does not bind the exact {spec.name} payload")
    if spec.name == "request":
        if request_context is None:
            fail("request package validation context is missing")
        validate_request_payload(
            payloads,
            request_context.trust_data,
            service=args.service,
            target=args.target,
            request_id=args.request_id,
            inventory=request_context.inventory,
            transport_host_key_sha256=args.transport_host_key_sha256,
        )
    else:
        validate_nonrequest_payload(
            spec,
            payloads,
            service=args.service,
            target=args.target,
            request_id=args.request_id,
        )
    validate_manifest(
        files["stage-manifest"],
        spec=spec,
        service=args.service,
        request_id=args.request_id,
        package_version=args.package_version,
        payloads=payloads,
    )


def download_generic(args: SimpleNamespace) -> dict[str, Any]:
    uid = os.geteuid()
    spec = STAGE_SPECS[args.stage]
    request_context: RequestValidationContext | None = None
    transport: TransportContext | None = None
    package = RequestPackage(
        service=args.service,
        target=args.target,
        request_id=args.request_id,
        package_name=spec.package_name(args.service),
        package_version=args.package_version,
        expires_epoch=None,
        files={},
        trust_files={},
        directories=[],
        stage=spec.name,
    )
    try:
        if spec.name == "request":
            request_context = load_request_context(args, uid)
        configuration_sources = (
            (
                request_context.inventory.source,
                request_context.trust_directory,
                *request_context.trust_files.values(),
            )
            if request_context is not None
            else ()
        )
        transport = load_transport(
            args, uid, configuration_sources=configuration_sources
        )
        package_id, remote = inspect_coordinate(
            transport.client,
            package,
            processing_attempts=args.processing_attempts,
            processing_interval=args.processing_interval,
        )
        if package_id is None:
            fail("exact GitLab package coordinate does not exist")
        if set(remote) != set(spec.package_files):
            fail(f"GitLab {spec.name} package is incomplete")
        initial = dict(remote)
        files: dict[str, bytes] = {}
        for name in spec.package_files:
            data = transport.client.download(
                package.package_name,
                package.package_version,
                name,
                MAX_FILE_SIZE[name],
            )
            if sha256(data) != initial[name]:
                fail(f"downloaded {name} differs from GitLab package-file SHA256")
            files[name] = data
        validate_downloaded_payload(args, spec, files, request_context)
        package_id_after, remote_after = inspect_coordinate(
            transport.client,
            package,
            processing_attempts=args.processing_attempts,
            processing_interval=args.processing_interval,
        )
        if package_id_after != package_id or remote_after != initial:
            fail("GitLab package coordinate changed during download")
        status = publish_destination(Path(args.destination_dir), files)
        if request_context is not None:
            request_context.recheck()
        for source in (
            transport.project.source,
            transport.token_source,
            transport.ca_source,
        ):
            source.recheck()
        return {
            "status": status,
            "stage": spec.name,
            "project_id": transport.project.project_id,
            "project_path": transport.project.project_path,
            "package_id": package_id,
            "package_name": package.package_name,
            "package_version": package.package_version,
            "destination_dir": os.fspath(Path(args.destination_dir)),
            "file_sha256": initial,
            "gitlab_authority_claimed": False,
        }
    finally:
        if transport is not None:
            transport.close()
        if request_context is not None:
            request_context.close()


def validate_args(args: SimpleNamespace) -> None:
    if not SERVICE.fullmatch(args.service):
        fail("service is not canonical")
    if not PRINCIPAL.fullmatch(args.target):
        fail("target is not canonical")
    if not HEX_32.fullmatch(args.request_id):
        fail("request ID is not 32 lowercase hexadecimal characters")
    if args.command == "publish-request":
        if args.token_type not in {"job", "private"}:
            fail("token type is invalid for request publication")
        if not HEX_64.fullmatch(args.transport_host_key_sha256):
            fail("transport host-key digest is invalid")
    else:
        if args.stage not in STAGE_SPECS:
            fail("package stage is invalid")
        if args.token_type not in {"job", "private", "deploy"}:
            fail("token type is invalid")
        version_pattern = (
            r"[0-9a-f]{32}"
            if args.stage in {"request", "response"}
            else r"[0-9a-f]{32}-[0-9a-f]{64}"
        )
        if re.fullmatch(version_pattern, args.package_version) is None:
            fail("package version has the wrong canonical stage shape")
        if not args.package_version.startswith(args.request_id):
            fail("package version does not start with the exact request ID")
        request_options = (
            args.inventory_record,
            args.trust_dir,
            args.transport_host_key_sha256,
        )
        if args.stage == "request":
            if any(value is None for value in request_options):
                fail(
                    "request transport requires --inventory-record, --trust-dir, "
                    "and --transport-host-key-sha256"
                )
            if not HEX_64.fullmatch(args.transport_host_key_sha256):
                fail("transport host-key digest is invalid")
        elif any(value is not None for value in request_options):
            fail("request-only validation options are forbidden for this stage")
    if args.timeout < 1 or args.timeout > 120:
        fail("GitLab timeout must be between 1 and 120 seconds")
    if args.processing_attempts < 1 or args.processing_attempts > 20:
        fail("processing attempts must be between 1 and 20")
    if args.processing_interval < 0 or args.processing_interval > 60:
        fail("processing interval must be between 0 and 60 seconds")


def _arguments(parsed: ParseResult) -> SimpleNamespace:
    values: dict[str, Any] = {
        "inventory_record": None,
        "trust_dir": None,
        "transport_host_key_sha256": None,
        "timeout": 30,
        "processing_attempts": 3,
        "processing_interval": 2,
    }
    integer_options = {
        "--timeout": "timeout",
        "--processing-attempts": "processing_attempts",
        "--processing-interval": "processing_interval",
    }
    for name, value in parsed.values.items():
        destination = name.removeprefix("--").replace("-", "_")
        if name in integer_options:
            try:
                value = int(value)
            except (TypeError, ValueError):
                fail(f"{name} must be an integer")
        values[destination] = value
    values["command"] = parsed.spec.route[-1]
    return SimpleNamespace(**values)


def gitlab_package(parsed: ParseResult) -> int:
    """Run one operator-side GitLab package transport operation."""

    if not isinstance(parsed, ParseResult):
        raise TypeError("parsed must be a ParseResult")
    os.umask(0o077)
    try:
        args = _arguments(parsed)
        validate_args(args)
        if args.command == "publish-request":
            result = publish_request(args)
        elif args.command == "publish":
            result = publish_generic(args)
        elif args.command == "download":
            result = download_generic(args)
        else:
            fail("unsupported command")
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except PackageError as error:
        raise ApplicationError(str(error)) from None
    except OSError as error:
        message = (
            os.strerror(error.errno)
            if isinstance(error.errno, int)
            else "filesystem operation failed"
        )
        raise ApplicationError(f"filesystem operation failed: {message}") from None
