"""Immutable publication and resolution of authenticated CSR responses."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import sys
from collections.abc import Mapping
from typing import NoReturn

from .csr_history import (
    CSR_ARTIFACT_FIELDS,
    CsrHistoryError,
    CsrPendingResponseAuthentication,
    authenticate_pending_response,
)
from .errors import ApplicationError
from .faults import PauseHook
from .filesystem import (
    ABSENT,
    DirectoryPolicy,
    FileIdentity,
    FilePolicy,
    FilesystemError,
    OpenedDirectory,
    identity_from_stat,
    fsync_directory,
)
from .operational import (
    acquire_operational_locks,
    get_service,
    load_inventory,
    prepare_control_state,
    require_generation_layout,
    require_inventory_readable,
    require_no_unresolved_state,
    require_pki_directory,
    require_program,
    resolve_paths,
    validate_service_name,
)
from .parser import ParseResult
from .publication import (
    PublicationAmbiguousError,
    PublicationDestinationExistsError,
    PublicationError,
    TreeReadiness,
    fsync_tree,
    publish_no_clobber,
    remove_exact_tree,
)
from .records import OrderedRecord, RecordError, RecordSpec


_OWNER = os.geteuid()
_DIRECTORY = DirectoryPolicy(owner=_OWNER, mode=0o700)
_FILE = FilePolicy(owner=_OWNER, mode=0o600, links=1, max_size=64 * 1024 * 1024)
_ARTIFACT_FILES = frozenset(
    ("artifact", "tls.crt", "ca-chain.crt", "fullchain.crt", "response", "response.sig")
)
_SOURCE_FILES = ("tls.crt", "ca-chain.crt", "fullchain.crt", "response", "response.sig")
_ARTIFACT_SPEC = RecordSpec(CSR_ARTIFACT_FIELDS, schema="1")
_REQUEST_ID = re.compile(r"[0-9a-f]{32}", re.ASCII)
_DIGEST = re.compile(r"[0-9a-f]{64}", re.ASCII)


def _die(message: str) -> NoReturn:
    raise ApplicationError(message)


def _retained_stage_warning(parent: OpenedDirectory, name: str) -> None:
    root = os.path.realpath(f"/proc/self/fd/{parent.fileno()}")
    print(
        "[WARN] Certificate export publication requires inspection; "
        f"retained evidence: {root}/{name}",
        file=sys.stderr,
        flush=True,
    )


def _recheck_source(source: CsrPendingResponseAuthentication) -> None:
    try:
        source()
    except CsrHistoryError as error:
        _die(str(error))


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    try:
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("write made no progress")
            view = view[written:]
    finally:
        view.release()


def _ensure_directory(parent: OpenedDirectory, name: str, path: str) -> OpenedDirectory:
    identity = parent.identity_at(name)
    if identity is ABSENT:
        try:
            os.mkdir(name, 0o700, dir_fd=parent.fileno())
            fsync_directory(parent)
        except OSError:
            _die(f"Cannot create certificate export directory: {path}")
    try:
        return parent.open_directory(name, policy=_DIRECTORY)
    except FilesystemError:
        _die(f"Certificate export directory is unsafe: {path}")


def _prepare_parent(pki_dir: str, service: str) -> OpenedDirectory:
    try:
        current = OpenedDirectory(pki_dir, policy=_DIRECTORY)
        path = pki_dir
        for name in ("export", "certificates", "v1", "artifacts", service):
            path = f"{path}/{name}"
            child = _ensure_directory(current, name, path)
            current.close()
            current = child
        return current
    except FilesystemError:
        _die("Cannot prepare certificate export directory")


def _manifest(
    service: str,
    request_id: str,
    source: CsrPendingResponseAuthentication,
) -> bytes:
    response = source.response
    values = {
        "schema": "1",
        "kind": "certificate-export",
        "service": service,
        "request_id": request_id,
        "operation": response["operation"],
        "target": response["target"],
        "source_kind": "csr-response",
        "source_response_sha256": source.response_sha256,
        "source_response_signature_sha256": source.response_signature_sha256,
        "certificate_sha256": source.certificate_sha256,
        "certificate_spki_sha256": source.certificate_spki_sha256,
        "chain_sha256": source.chain_sha256,
        "fullchain_sha256": source.fullchain_sha256,
        "issuer_root": response["issuer_root"],
        "issuer_intermediate": response["issuer_intermediate"],
        "serial": response["serial"],
        "not_before_epoch": response["not_before_epoch"],
        "not_after_epoch": response["not_after_epoch"],
        "candidate_state": "pending",
        "deployment_state": "unfinalized",
        "response_principal": response["response_principal"],
        "created_epoch": response["created_epoch"],
    }
    try:
        return _ARTIFACT_SPEC.serialize(values)
    except RecordError:
        _die("Cannot serialize certificate export manifest")


def _write_file(parent: OpenedDirectory, name: str, data: bytes) -> FileIdentity:
    descriptor = -1
    try:
        descriptor = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=parent.fileno(),
        )
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, data)
        os.fsync(descriptor)
        identity = identity_from_stat(os.fstat(descriptor))
        _FILE.validate(identity)
        if identity.size != len(data) or parent.identity_at(name) != identity:
            raise OSError("staged identity mismatch")
        return identity
    except (OSError, FilesystemError):
        _die(f"Cannot stage CSR response {name}")
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _create_stage(
    parent: OpenedDirectory,
    request_id: str,
    source: CsrPendingResponseAuthentication,
    manifest: bytes,
) -> tuple[str, OpenedDirectory, FileIdentity, TreeReadiness]:
    for _attempt in range(16):
        name = f".platform-pki-certificate-export.{request_id}.{secrets.token_hex(16)}"
        try:
            os.mkdir(name, 0o700, dir_fd=parent.fileno())
            break
        except FileExistsError:
            continue
        except OSError:
            _die("Cannot create certificate export stage")
    else:
        _die("Cannot create certificate export stage")
    stage: OpenedDirectory | None = None
    readiness: TreeReadiness | None = None
    identity: FileIdentity | None = None
    try:
        stage = parent.open_directory(name, policy=_DIRECTORY)
        for file_name in _SOURCE_FILES:
            _write_file(stage, file_name, source.files[file_name])
        _write_file(stage, "artifact", manifest)
        stage.close()
        stage = parent.open_directory(name, policy=_DIRECTORY)
        identity = stage.recheck()
        readiness = fsync_tree(stage, parent, name)
        return name, stage, identity, readiness
    except BaseException:
        if stage is not None:
            stage.close()
        try:
            partial = parent.open_directory(name, policy=_DIRECTORY)
            try:
                identity = partial.recheck()
                readiness = fsync_tree(partial, parent, name)
            finally:
                partial.close()
            remove_exact_tree(parent, name, identity, readiness)
        except (FilesystemError, PublicationError):
            retained = os.path.realpath(f"/proc/self/fd/{parent.fileno()}")
            print(
                "[WARN] Certificate export staging evidence retained for inspection: "
                f"{retained}/{name}",
                file=sys.stderr,
            )
        raise


def _load_artifact(
    path: str,
    service: str,
    request_id: str,
    source: CsrPendingResponseAuthentication,
    expected_digest: str | None = None,
) -> tuple[OpenedDirectory, FileIdentity, Mapping[str, FileIdentity], str, OrderedRecord]:
    try:
        directory = OpenedDirectory(path, policy=_DIRECTORY)
        if frozenset(os.listdir(directory.fileno())) != _ARTIFACT_FILES:
            _die(f"Certificate export artifact has unexpected or unsafe entries: {path}")
        files: dict[str, FileIdentity] = {}
        data: dict[str, bytes] = {}
        for name in sorted(_ARTIFACT_FILES):
            with directory.open_file(name, policy=_FILE) as opened:
                data[name] = opened.read(_FILE.max_size or 0)
                files[name] = opened.recheck()
        identity = directory.recheck()
    except FilesystemError:
        _die(f"Certificate export artifact has unexpected or unsafe entries: {path}")
    try:
        record = _ARTIFACT_SPEC.parse(data["artifact"])
    except RecordError as error:
        directory.close()
        if "end with exactly one newline" in str(error):
            _die("Certificate export manifest is not canonically newline-terminated")
        _die(f"Certificate export manifest is invalid: {error}")
    response = source.response
    expected = _manifest(service, request_id, source)
    if record.to_bytes() != expected:
        directory.close()
        _die("Certificate export manifest binding failed")
    expected_files = {
        "tls.crt": source.certificate_sha256,
        "ca-chain.crt": source.chain_sha256,
        "fullchain.crt": source.fullchain_sha256,
        "response": source.response_sha256,
        "response.sig": source.response_signature_sha256,
    }
    if any(hashlib.sha256(data[name]).hexdigest() != digest for name, digest in expected_files.items()):
        directory.close()
        _die("Certificate export file digest validation failed")
    for name in _SOURCE_FILES:
        if data[name] != source.files[name]:
            directory.close()
            _die(f"Exported {name} differs between the pending candidate and response")
    manifest_digest = hashlib.sha256(data["artifact"]).hexdigest()
    if expected_digest is not None and manifest_digest != expected_digest:
        directory.close()
        _die("Certificate export manifest digest does not match --manifest-sha256")
    _recheck_source(source)
    try:
        directory.recheck()
        for name, expected_identity in files.items():
            with directory.open_file(name, policy=_FILE, expected_identity=expected_identity) as opened:
                opened.recheck()
    except FilesystemError:
        directory.close()
        _die("Certificate export artifact changed after validation")
    return directory, identity, files, manifest_digest, record


def _publish(
    pki_dir: str,
    service: str,
    request_id: str,
    source: CsrPendingResponseAuthentication,
    pause: PauseHook,
) -> int:
    parent = _prepare_parent(pki_dir, service)
    path = f"{pki_dir}/export/certificates/v1/artifacts/{service}/{request_id}"
    try:
        try:
            destination_identity = parent.identity_at(request_id)
        except FilesystemError:
            _die("Certificate export destination is unsafe")
        if destination_identity is not ABSENT:
            if (
                not isinstance(destination_identity, FileIdentity)
                or destination_identity.kind != "directory"
            ):
                _die("Certificate export destination is unsafe")
            artifact, _identity, _files, digest, _record = _load_artifact(
                path, service, request_id, source
            )
            artifact.close()
            print(f"[OK] Kept exact immutable certificate export: {path}")
            print(f"manifest_sha256={digest}")
            return 0
        manifest = _manifest(service, request_id, source)
        stage_name, stage, stage_identity, readiness = _create_stage(
            parent, request_id, source, manifest
        )
        published = False
        try:
            pause("publish-before-rename")
            _recheck_source(source)
            publish_no_clobber(
                parent,
                stage_name,
                stage_identity,
                parent,
                request_id,
                readiness=readiness,
                pre_publish_check=lambda: _recheck_source(source),
            )
            published = True
        except PublicationDestinationExistsError:
            _die("Cannot publish immutable certificate export")
        except PublicationAmbiguousError:
            _die("Certificate export publication requires inspection")
        except PublicationError as error:
            _die(str(error))
        finally:
            stage.close()
            if not published:
                try:
                    remove_exact_tree(parent, stage_name, stage_identity, readiness)
                except PublicationError:
                    _retained_stage_warning(parent, stage_name)
        artifact, _identity, _files, digest, _record = _load_artifact(
            path, service, request_id, source
        )
        artifact.close()
        print(f"[OK] Published immutable unfinalized certificate export: {path}")
        print(f"manifest_sha256={digest}")
        return 0
    finally:
        parent.close()


def _resolve(
    pki_dir: str,
    service: str,
    request_id: str,
    source: CsrPendingResponseAuthentication,
    digest: str,
    output_format: str,
    pause: PauseHook,
) -> int:
    if _DIGEST.fullmatch(digest) is None:
        _die("--manifest-sha256 must be a lowercase SHA-256 digest")
    path = f"{pki_dir}/export/certificates/v1/artifacts/{service}/{request_id}"
    artifact, identity, files, actual, _record = _load_artifact(
        path, service, request_id, source, digest
    )
    try:
        absolute = os.path.realpath(f"/proc/self/fd/{artifact.fileno()}")
        pause("resolver-before-output")
        try:
            artifact.recheck()
            if artifact.identity != identity:
                _die("Certificate export artifact directory identity changed after validation")
        except FilesystemError:
            _die("Certificate export artifact directory identity changed after validation")
        try:
            for name, expected in files.items():
                try:
                    with artifact.open_file(
                        name, policy=_FILE, expected_identity=expected
                    ) as opened:
                        opened.recheck()
                except FilesystemError:
                    _die(
                        f"Certificate export artifact file identity changed after validation: {name}"
                    )
        except FilesystemError:
            _die("Certificate export artifact changed after validation")
        _recheck_source(source)
        if output_format == "path":
            print(absolute)
        else:
            print(
                json.dumps(
                    {
                        "schema": 1,
                        "kind": "certificate-export-resolution",
                        "service": service,
                        "request_id": request_id,
                        "manifest_sha256": actual,
                        "path": absolute,
                        "candidate_state": "pending",
                        "deployment_state": "unfinalized",
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
        return 0
    finally:
        artifact.close()


def certificate_export(parsed: ParseResult) -> int:
    """Run one parsed certificate-export action."""

    environment = dict(os.environ)
    os.umask(0o077)
    service_name = parsed["service"]
    request_id = parsed["--request-id"]
    validate_service_name(service_name)
    if _REQUEST_ID.fullmatch(request_id) is None:
        _die("Certificate export request ID is invalid")
    for program in ("openssl", "ssh-keygen"):
        require_program(program, environment)
    paths = resolve_paths(parsed.values, environment)
    require_pki_directory(paths.pki_dir)
    prepare_control_state(paths.pki_dir)
    pause = PauseHook(
        pause_at=environment.get("PLATFORM_PKI_CERTIFICATE_EXPORT_PAUSE_AT"),
        marker=environment.get("PLATFORM_PKI_CERTIFICATE_EXPORT_PAUSE_MARKER"),
        release=environment.get("PLATFORM_PKI_CERTIFICATE_EXPORT_PAUSE_RELEASE"),
    )
    with acquire_operational_locks(paths.pki_dir, "export"):
        require_no_unresolved_state(paths.pki_dir)
        require_generation_layout(paths.pki_dir)
        inventory_path = require_inventory_readable(paths.pki_dir)
        inventory = load_inventory(inventory_path)
        service = get_service(inventory, service_name, inventory_path)
        if service.key_custody != "host-local":
            _die("Certificate-only CSR export requires key_custody: host-local")
        try:
            source = authenticate_pending_response(
                paths.pki_dir,
                service,
                request_id,
                environment,
                pause_hook=pause,
            )
        except CsrHistoryError as error:
            _die(str(error))
        if parsed.spec.route == ("certificate-export", "publish"):
            return _publish(paths.pki_dir, service_name, request_id, source, pause)
        return _resolve(
            paths.pki_dir,
            service_name,
            request_id,
            source,
            parsed["--manifest-sha256"],
            parsed["--format"],
            pause,
        )
