"""Transfer fixed host-local PKI frames over one host-key-pinned SSH command."""

from __future__ import annotations

import base64
import binascii
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import selectors
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, NoReturn, Sequence

from .errors import ApplicationError
from .parser import ParseResult


HEADER_LIMIT = 16 * 1024
SSH_TIMEOUT_SECONDS = 120
REQUEST_NAMES = ("tls.csr", "request", "request.sig")
RESPONSE_NAMES = (
    "artifact", "tls.crt", "ca-chain.crt", "fullchain.crt", "response", "response.sig"
)
EVIDENCE_NAMES = (
    "deployment", "deployment.sig", "validation-boundary", "validation-result",
    "validation-result.sig",
)
OUTCOME_NAMES = (
    "outcome", "outcome.sig", "deployment", "deployment.sig",
    "deployers.allowed_signers", "decision",
)
NAMES_BY_KIND = {
    "request": REQUEST_NAMES,
    "response": RESPONSE_NAMES,
    "evidence": EVIDENCE_NAMES,
    "outcome": OUTCOME_NAMES,
}
MAX_SIZES = {
    "tls.csr": 65536,
    "request": 16384,
    "request.sig": 16384,
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
}
MAX_FRAME = HEADER_LIMIT + sum(MAX_SIZES.values())
HEX_32 = re.compile(r"[0-9a-f]{32}\Z", re.ASCII)
HEX_64 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
SERVICE_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,62}\Z", re.ASCII)
IDENTITY_RE = re.compile(r"[a-z0-9][a-z0-9.-]{0,252}\Z", re.ASCII)
USER_RE = re.compile(r"[a-z_][a-z0-9_-]{0,31}\Z", re.ASCII)
PATH_COMPONENT_RE = re.compile(r"[A-Za-z0-9_@+=:,.-]+\Z", re.ASCII)
KEY_ALGORITHM_RE = re.compile(r"(?:ssh-ed25519|ecdsa-sha2-nistp(?:256|384|521)|rsa-sha2-(?:256|512))\Z", re.ASCII)
HOST_DIGEST_RE = re.compile(r"SHA256:[A-Za-z0-9+/]{43}\Z", re.ASCII)


class DirectExchangeError(RuntimeError):
    pass


def fail(message: str) -> NoReturn:
    raise DirectExchangeError(message)


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require_request_id(value: str) -> str:
    if HEX_32.fullmatch(value) is None:
        fail("request ID is not canonical")
    return value


def require_digest(value: str, label: str) -> str:
    if HEX_64.fullmatch(value) is None:
        fail(f"{label} is not a canonical SHA-256 digest")
    return value


def canonical_path(value: str, label: str) -> str:
    if (
        not isinstance(value, str) or not value.startswith("/") or value == "/"
        or os.path.normpath(value) != value
        or any(PATH_COMPONENT_RE.fullmatch(part) is None for part in value.split("/")[1:])
    ):
        fail(f"{label} is not an absolute canonical non-root path")
    return value


def validate_ancestors(path: str, label: str) -> None:
    current = "/"
    for component in os.path.dirname(path).split("/")[1:]:
        current = os.path.join(current, component)
        metadata = os.lstat(current)
        mode = stat.S_IMODE(metadata.st_mode)
        if (
            not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid not in {0, os.geteuid()}
            or (mode & 0o022 and not mode & stat.S_ISVTX)
        ):
            fail(f"{label} has an unsafe ancestor")


def parse_record(data: bytes, label: str) -> dict[str, str]:
    if not data.endswith(b"\n") or b"\r" in data or b"\x00" in data:
        fail(f"{label} is not canonical LF-terminated text")
    try:
        lines = data.decode("ascii").splitlines()
    except UnicodeDecodeError:
        fail(f"{label} is not ASCII")
    result: dict[str, str] = {}
    for line in lines:
        if "=" not in line:
            fail(f"{label} contains a malformed field")
        key, value = line.split("=", 1)
        if not key or key in result or not value:
            fail(f"{label} contains an unsafe field")
        result[key] = value
    return result


def protected_file(path: str, label: str, *, maximum: int | None = None) -> bytes:
    canonical_path(path, label)
    validate_ancestors(path, label)
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as error:
        fail(f"cannot open {label}: {error.strerror}")
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
            or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != 0o600
            or (maximum is not None and (before.st_size <= 0 or before.st_size > maximum))
        ):
            fail(f"{label} has unsafe metadata")
        chunks: list[bytes] = []
        remaining = (maximum + 1) if maximum is not None else before.st_size + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(descriptor)
        rebound = os.lstat(path)
        identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        if (
            len(data) != before.st_size
            or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) != identity
            or (rebound.st_dev, rebound.st_ino, rebound.st_size, rebound.st_mtime_ns, rebound.st_ctime_ns) != identity
        ):
            fail(f"{label} changed while being read")
        validate_ancestors(path, label)
        return data
    finally:
        os.close(descriptor)


def validate_directory(path: str, label: str) -> None:
    canonical_path(path, label)
    validate_ancestors(path, label)
    metadata = os.lstat(path)
    if (
        not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        fail(f"{label} is not an owner-only directory")


def ensure_directory(path: str, label: str) -> bool:
    canonical_path(path, label)
    parent = os.path.dirname(path)
    if not os.path.isdir(parent) or os.path.islink(parent):
        fail(f"parent of {label} is unavailable or unsafe")
    created = False
    try:
        os.mkdir(path, 0o700)
        created = True
        descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except FileExistsError:
        pass
    validate_directory(path, label)
    return created


def read_tree(path: str, names: Sequence[str], label: str) -> dict[str, bytes]:
    validate_directory(path, label)
    if set(os.listdir(path)) != set(names):
        fail(f"{label} does not contain the exact file set")
    return {
        name: protected_file(os.path.join(path, name), f"{label} file {name}", maximum=MAX_SIZES[name])
        for name in names
    }


def publish_tree(path: str, files: Mapping[str, bytes], names: Sequence[str], label: str) -> str:
    created_directory = ensure_directory(path, label)
    created: dict[str, tuple[int, int]] = {}
    try:
        entries = set(os.listdir(path))
        if not entries.issubset(names):
            fail(f"{label} contains unexpected entries")
        for name in names:
            destination = os.path.join(path, name)
            if name in entries:
                if protected_file(destination, f"{label} file {name}", maximum=MAX_SIZES[name]) != files[name]:
                    fail(f"{label} conflicts at {name}")
                continue
            descriptor = os.open(
                destination,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
            )
            try:
                view = memoryview(files[name])
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        fail(f"cannot write {label} file {name}")
                    view = view[written:]
                os.fsync(descriptor)
                metadata = os.fstat(descriptor)
                created[name] = (metadata.st_dev, metadata.st_ino)
            finally:
                os.close(descriptor)
        directory = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        if read_tree(path, names, label) != files:
            fail(f"{label} changed during publication")
        return "existing" if not created else "stored"
    except Exception:
        for name, identity in created.items():
            destination = os.path.join(path, name)
            try:
                metadata = os.lstat(destination)
                if (metadata.st_dev, metadata.st_ino) != identity:
                    fail(f"created {label} file identity became ambiguous")
            except FileNotFoundError:
                fail(f"created {label} file disappeared")
        for name in created:
            os.unlink(os.path.join(path, name))
        if created_directory and not os.listdir(path):
            os.rmdir(path)
        raise


def frame_header(kind: str, files: Mapping[str, bytes], coordinates: Mapping[str, str], service: str, target: str) -> dict[str, object]:
    names = NAMES_BY_KIND[kind]
    return {
        "files": [
            {"name": name, "sha256": sha256(files[name]), "size": len(files[name])}
            for name in names
        ],
        "kind": kind,
        **coordinates,
        "schema": 1,
        "service": service,
        "target": target,
    }


def encode_frame(kind: str, files: Mapping[str, bytes], coordinates: Mapping[str, str], service: str, target: str) -> bytes:
    if tuple(files) != NAMES_BY_KIND[kind]:
        fail("local files are not in canonical frame order")
    header = canonical_json(frame_header(kind, files, coordinates, service, target))
    if len(header) + 1 > HEADER_LIMIT:
        fail("frame header exceeds the fixed bound")
    return header + b"\n" + b"".join(files[name] for name in NAMES_BY_KIND[kind])


def decode_frame(data: bytes, kind: str, coordinates: Mapping[str, str]) -> tuple[dict[str, bytes], str, str]:
    if len(data) > MAX_FRAME:
        fail("framed stream exceeds the fixed bound")
    newline = data.find(b"\n", 0, HEADER_LIMIT)
    if newline <= 0:
        fail("framed stream lacks one bounded header line")
    encoded = data[:newline]
    try:
        header = json.loads(encoded)
    except (UnicodeDecodeError, ValueError):
        fail("framed stream header is invalid JSON")
    expected_keys = {"files", "kind", "schema", "service", "target", *coordinates}
    if (
        not isinstance(header, dict) or set(header) != expected_keys
        or canonical_json(header) != encoded or header["schema"] != 1
        or header["kind"] != kind
        or SERVICE_RE.fullmatch(header.get("service", "")) is None
        or IDENTITY_RE.fullmatch(header.get("target", "")) is None
        or any(header[name] != value for name, value in coordinates.items())
    ):
        fail("framed stream header differs from fixed coordinates")
    names = NAMES_BY_KIND[kind]
    entries = header["files"]
    if not isinstance(entries, list) or len(entries) != len(names):
        fail("framed stream file metadata has an invalid count")
    files: dict[str, bytes] = {}
    offset = newline + 1
    for name, entry in zip(names, entries, strict=True):
        if (
            not isinstance(entry, dict) or set(entry) != {"name", "sha256", "size"}
            or entry["name"] != name or not isinstance(entry["size"], int)
            or isinstance(entry["size"], bool) or entry["size"] <= 0
            or entry["size"] > MAX_SIZES[name]
            or not isinstance(entry["sha256"], str) or HEX_64.fullmatch(entry["sha256"]) is None
        ):
            fail(f"framed stream metadata is unsafe for {name}")
        end = offset + entry["size"]
        if end > len(data):
            fail("framed stream payload is truncated")
        files[name] = data[offset:end]
        if sha256(files[name]) != entry["sha256"]:
            fail(f"framed stream digest differs for {name}")
        offset = end
    if offset != len(data):
        fail("framed stream has trailing payload bytes")
    return files, header["service"], header["target"]


@dataclass(frozen=True)
class Endpoint:
    host: str
    port: int
    user: str
    identity_path: str
    known_hosts_path: str
    expected_host_key_sha256: str
    transport_host_key_sha256: str
    remote_helper_path: str
    identity_data: bytes
    known_hosts_data: bytes


def host_token(host: str, port: int) -> str:
    token = host if ":" not in host else f"[{host}]"
    return token if port == 22 else f"[{host}]:{port}"


def load_endpoint(path: str) -> Endpoint:
    data = protected_file(path, "endpoint record", maximum=HEADER_LIMIT)
    if not data.endswith(b"\n") or data.count(b"\n") != 1:
        fail("endpoint record is not one canonical JSON line")
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, ValueError):
        fail("endpoint record is invalid JSON")
    keys = {
        "expected_host_key_sha256", "host", "identity_path", "known_hosts_path",
        "port", "remote_helper_path", "schema", "user",
    }
    if (
        not isinstance(value, dict) or set(value) != keys or value["schema"] != 1
        or canonical_json(value) + b"\n" != data
        or not isinstance(value["port"], int) or isinstance(value["port"], bool)
        or not 1 <= value["port"] <= 65535
        or USER_RE.fullmatch(value.get("user", "")) is None
        or HOST_DIGEST_RE.fullmatch(value.get("expected_host_key_sha256", "")) is None
    ):
        fail("endpoint record violates the fixed schema")
    host = value["host"]
    try:
        parsed_ip = ipaddress.ip_address(host)
        if str(parsed_ip) != host:
            fail("endpoint host IP is not canonical")
    except ValueError:
        if IDENTITY_RE.fullmatch(host) is None:
            fail("endpoint host is not canonical")
    identity_path = canonical_path(value["identity_path"], "identity path")
    known_hosts_path = canonical_path(value["known_hosts_path"], "known-hosts path")
    helper = canonical_path(value["remote_helper_path"], "remote helper path")
    if os.path.basename(helper) != "platform-pki-host-local-exchange":
        fail("endpoint record selects an unexpected remote helper")
    identity_data = protected_file(identity_path, "SSH identity", maximum=HEADER_LIMIT)
    known_hosts_data = protected_file(
        known_hosts_path, "known-hosts file", maximum=65536
    )
    transport_host_key_sha256 = validate_known_host_record(
        host, value["port"], known_hosts_data, value["expected_host_key_sha256"]
    )
    endpoint = Endpoint(
        host=host, port=value["port"], user=value["user"],
        identity_path=identity_path, known_hosts_path=known_hosts_path,
        expected_host_key_sha256=value["expected_host_key_sha256"],
        transport_host_key_sha256=transport_host_key_sha256,
        remote_helper_path=helper,
        identity_data=identity_data,
        known_hosts_data=known_hosts_data,
    )
    validate_known_host(endpoint)
    return endpoint


def validate_known_host_record(
    host: str, port: int, data: bytes, expected_digest: str
) -> str:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        fail("known-hosts file is not ASCII")
    if not text.endswith("\n") or "\r" in text or "\x00" in text:
        fail("known-hosts file is not canonical text")
    lines = text.splitlines()
    if len(lines) != 1:
        fail("known-hosts file must contain exactly one key record")
    parts = lines[0].split(" ")
    if len(parts) != 3 or parts[0] != host_token(host, port) or KEY_ALGORITHM_RE.fullmatch(parts[1]) is None:
        fail("known-hosts record differs from the endpoint")
    try:
        blob = base64.b64decode(parts[2], validate=True)
    except (binascii.Error, ValueError):
        fail("known-hosts key blob is invalid")
    if not blob or base64.b64encode(blob).decode("ascii") != parts[2]:
        fail("known-hosts key blob is noncanonical")
    if len(blob) < 4:
        fail("known-hosts key blob is malformed")
    algorithm_length = int.from_bytes(blob[:4], "big")
    if 4 + algorithm_length > len(blob):
        fail("known-hosts key blob is malformed")
    try:
        blob_algorithm = blob[4 : 4 + algorithm_length].decode("ascii")
    except UnicodeDecodeError:
        fail("known-hosts key algorithm is malformed")
    if blob_algorithm != parts[1]:
        fail("known-hosts key algorithm differs from its record")
    digest = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")
    if digest != expected_digest:
        fail("known-hosts key digest differs from the endpoint pin")
    return hashlib.sha256(blob).hexdigest()


def validate_known_host(endpoint: Endpoint) -> None:
    digest = validate_known_host_record(
        endpoint.host,
        endpoint.port,
        endpoint.known_hosts_data,
        endpoint.expected_host_key_sha256,
    )
    if digest != endpoint.transport_host_key_sha256:
        fail("known-hosts key digest changed after endpoint validation")


def ssh_argv(
    endpoint: Endpoint,
    remote_command: str,
    coordinates: Sequence[str],
    *,
    identity_path: str,
    known_hosts_path: str,
) -> list[str]:
    destination_host = endpoint.host if ":" not in endpoint.host else f"[{endpoint.host}]"
    return [
        "ssh", "-F", "/dev/null", "-T",
        "-o", "BatchMode=yes",
        "-o", "IdentitiesOnly=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", f"UserKnownHostsFile={known_hosts_path}",
        "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", "UpdateHostKeys=no",
        "-o", "VerifyHostKeyDNS=no",
        "-o", "ForwardAgent=no",
        "-o", "ForwardX11=no",
        "-o", "ClearAllForwardings=yes",
        "-o", "PermitLocalCommand=no",
        "-o", "ProxyCommand=none",
        "-o", "ProxyJump=none",
        "-o", "CanonicalizeHostname=no",
        "-p", str(endpoint.port), "-i", identity_path,
        f"{endpoint.user}@{destination_host}",
        "sudo", "-n", "--", endpoint.remote_helper_path, remote_command,
        *coordinates,
    ]


def sealed_memfd(name: str, data: bytes) -> int:
    descriptor = os.memfd_create(
        name, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING
    )
    try:
        os.fchmod(descriptor, 0o600)
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                fail("cannot materialize anonymous SSH input")
            view = view[written:]
        os.lseek(descriptor, 0, os.SEEK_SET)
        fcntl.fcntl(
            descriptor,
            fcntl.F_ADD_SEALS,
            fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE,
        )
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def run_bounded(
    argv: Sequence[str], input_data: bytes | None
) -> tuple[int, bytes, bytes]:
    process = subprocess.Popen(
        argv,
        stdin=subprocess.PIPE if input_data is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        bufsize=0,
    )
    assert process.stdout is not None and process.stderr is not None
    selector = selectors.DefaultSelector()
    stdout = bytearray()
    stderr = bytearray()
    input_view = memoryview(input_data or b"")
    selector.register(process.stdout, selectors.EVENT_READ, (stdout, MAX_FRAME, "output"))
    selector.register(process.stderr, selectors.EVENT_READ, (stderr, HEADER_LIMIT, "diagnostics"))
    if process.stdin is not None:
        selector.register(process.stdin, selectors.EVENT_WRITE, None)
    for stream in (process.stdin, process.stdout, process.stderr):
        if stream is not None:
            os.set_blocking(stream.fileno(), False)
    deadline = time.monotonic() + SSH_TIMEOUT_SECONDS
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(argv, SSH_TIMEOUT_SECONDS)
            events = selector.select(remaining)
            if not events:
                raise subprocess.TimeoutExpired(argv, SSH_TIMEOUT_SECONDS)
            for key, _mask in events:
                stream = key.fileobj
                if key.data is None:
                    try:
                        written = os.write(stream.fileno(), input_view[:65536])
                        input_view = input_view[written:]
                    except BlockingIOError:
                        continue
                    except BrokenPipeError:
                        input_view = memoryview(b"")
                    if not input_view:
                        selector.unregister(stream)
                        stream.close()
                    continue
                buffer, limit, label = key.data
                try:
                    chunk = os.read(
                        stream.fileno(), min(65536, limit + 1 - len(buffer))
                    )
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(stream)
                    stream.close()
                    continue
                buffer.extend(chunk)
                if len(buffer) > limit:
                    fail(f"pinned SSH exchange {label} exceeded its size limit")
        returncode = process.wait(timeout=max(0.001, deadline - time.monotonic()))
        return returncode, bytes(stdout), bytes(stderr)
    except BaseException:
        process.kill()
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None and not stream.closed:
                stream.close()
        process.wait()
        raise
    finally:
        selector.close()


def invoke(endpoint: Endpoint, remote_command: str, coordinates: Sequence[str], input_data: bytes | None) -> bytes:
    identity_descriptor = -1
    known_hosts_descriptor = -1
    try:
        identity_descriptor = sealed_memfd("platform-pki-identity", endpoint.identity_data)
        known_hosts_descriptor = sealed_memfd(
            "platform-pki-known-hosts", endpoint.known_hosts_data
        )
        returncode, stdout, stderr = run_bounded(
            ssh_argv(
                endpoint,
                remote_command,
                coordinates,
                identity_path=f"/proc/{os.getpid()}/fd/{identity_descriptor}",
                known_hosts_path=f"/proc/{os.getpid()}/fd/{known_hosts_descriptor}",
            ),
            input_data,
        )
    except (OSError, subprocess.TimeoutExpired):
        fail("pinned SSH exchange invocation failed")
    finally:
        for descriptor in (identity_descriptor, known_hosts_descriptor):
            if descriptor >= 0:
                os.close(descriptor)
    if returncode != 0:
        fail("remote exchange helper rejected the transfer")
    if stderr:
        fail("remote exchange helper emitted unexpected diagnostics")
    return stdout


def coordinates(request_id: str, artifact: str | None = None, deployment: str | None = None, outcome: str | None = None) -> dict[str, str]:
    result = {"request_id": require_request_id(request_id)}
    for name, value in (
        ("artifact_sha256", artifact), ("deployment_sha256", deployment),
        ("outcome_sha256", outcome),
    ):
        if value is not None:
            result[name] = require_digest(value, name.replace("_", " "))
    return result


def validate_push_records(kind: str, files: Mapping[str, bytes], values: Mapping[str, str]) -> tuple[str, str]:
    primary_name = "artifact" if kind == "response" else "outcome"
    primary = parse_record(files[primary_name], f"{kind} primary record")
    service = primary.get("service", "")
    target = primary.get("target", "")
    if SERVICE_RE.fullmatch(service) is None or IDENTITY_RE.fullmatch(target) is None or primary.get("request_id") != values["request_id"]:
        fail(f"{kind} primary record differs from fixed coordinates")
    if kind == "response":
        if sha256(files["artifact"]) != values["artifact_sha256"]:
            fail("response artifact differs from its coordinate")
    else:
        deployment = parse_record(files["deployment"], "outcome deployment")
        decision = parse_record(files["decision"], "outcome decision")
        for record in (deployment, decision):
            if record.get("service") != service or record.get("target") != target or record.get("request_id") != values["request_id"]:
                fail("outcome records have inconsistent coordinates")
        if (
            sha256(files["outcome"]) != values["outcome_sha256"]
            or sha256(files["deployment"]) != values["deployment_sha256"]
            or primary.get("artifact_manifest_sha256") != values["artifact_sha256"]
            or primary.get("deployment_sha256") != values["deployment_sha256"]
        ):
            fail("outcome files differ from supplied coordinates")
    return service, target


def parse_remote_result(data: bytes, expected: Mapping[str, str]) -> dict[str, object]:
    if len(data) > HEADER_LIMIT or not data.endswith(b"\n") or data.count(b"\n") != 1:
        fail("remote helper returned invalid result metadata")
    encoded = data[:-1]
    try:
        result = json.loads(encoded)
    except (UnicodeDecodeError, ValueError):
        fail("remote helper returned invalid result metadata")
    if not isinstance(result, dict):
        fail("remote helper returned invalid result metadata")
    expected_result = {**expected, "status": result.get("status")}
    if "outcome_sha256" in expected:
        expected_result["stage_id"] = (
            f"pki-outcome-v1:{expected['request_id']}:{expected['artifact_sha256']}:"
            f"{expected['deployment_sha256']}:{expected['outcome_sha256']}"
        )
    if (
        canonical_json(result) != encoded
        or set(result) != set(expected_result)
        or any(result.get(name) != value for name, value in expected.items())
        or result.get("status") not in {"staged", "existing"}
        or any(result.get(name) != value for name, value in expected_result.items())
    ):
        fail("remote helper result differs from transfer coordinates")
    return result


def _run_direct_exchange(parsed: ParseResult) -> dict[str, object]:
    command = parsed.spec.route[-1]
    endpoint = load_endpoint(canonical_path(parsed["endpoint"], "endpoint record path"))
    if command == "request-pull":
        values = coordinates(parsed["request_id"])
        data = invoke(endpoint, "export-request", tuple(values.values()), None)
        files, service, target = decode_frame(data, "request", values)
        destination_dir = canonical_path(
            parsed["output_dir"], "request output directory"
        )
        status_value = publish_tree(
            destination_dir, files, REQUEST_NAMES, "request output directory"
        )
        return {
            **values,
            "service": service,
            "status": status_value,
            "target": target,
            "transport_host_key_sha256": endpoint.transport_host_key_sha256,
            "destination_dir": destination_dir,
        }
    if command == "evidence-pull":
        values = coordinates(
            parsed["request_id"],
            parsed["artifact_sha256"],
            parsed["deployment_sha256"],
        )
        data = invoke(endpoint, "export-evidence", tuple(values.values()), None)
        files, service, target = decode_frame(data, "evidence", values)
        destination_dir = canonical_path(
            parsed["output_dir"], "evidence output directory"
        )
        status_value = publish_tree(
            destination_dir, files, EVIDENCE_NAMES, "evidence output directory"
        )
        return {
            **values,
            "service": service,
            "status": status_value,
            "target": target,
            "destination_dir": destination_dir,
        }
    if command == "response-push":
        kind = "response"
        remote_command = "stage-response"
        values = coordinates(parsed["request_id"], parsed["artifact_sha256"])
    elif command == "outcome-push":
        kind = "outcome"
        remote_command = "stage-outcome"
        values = coordinates(
            parsed["request_id"],
            parsed["artifact_sha256"],
            parsed["deployment_sha256"],
            parsed["outcome_sha256"],
        )
    else:
        fail("direct exchange action is unavailable")
    files = read_tree(canonical_path(parsed["input_dir"], f"{kind} input directory"), NAMES_BY_KIND[kind], f"{kind} input directory")
    service, target = validate_push_records(kind, files, values)
    frame = encode_frame(kind, files, values, service, target)
    return parse_remote_result(
        invoke(endpoint, remote_command, tuple(values.values()), frame), values
    )


def direct_exchange(parsed: ParseResult) -> int:
    """Run one parsed operator-side direct exchange action."""

    os.umask(0o077)
    try:
        result = _run_direct_exchange(parsed)
        sys.stdout.buffer.write(canonical_json(result) + b"\n")
        return 0
    except (DirectExchangeError, OSError, ValueError) as error:
        raise ApplicationError(str(error)) from None
