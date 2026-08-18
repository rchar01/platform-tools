"""Authenticated immutable export of terminal host-local CSR signer outcomes."""

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
    CsrHistoryError,
    CsrOutcomeExportAuthentication,
    authenticate_outcome_export_source,
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
    OpenedFile,
    fsync_directory,
    identity_from_stat,
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
from .paths import PathError, validate_absolute_path
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
from .ssh_keys import run_ssh_keygen
from .subprocesses import ProcessResult, run_process


CSR_OUTCOME_FIELDS = tuple(
    """schema kind service target request_id operation request_sha256
response_sha256 response_signature_sha256 candidate_sha256
artifact_manifest_sha256 certificate_sha256 certificate_spki_sha256 chain_sha256
fullchain_sha256 deployment_sha256 deployment_signature_sha256 deployers_sha256
decision_sha256 action state resulting_active_request_id created_epoch
outcome_principal""".split()
)

_OWNER = os.geteuid()
_DIRECTORY = DirectoryPolicy(owner=_OWNER, mode=0o700)
_FILE = FilePolicy(owner=_OWNER, mode=0o600, links=1, max_size=64 * 1024 * 1024)
_KEY_FILE = FilePolicy(owner=_OWNER, forbidden_bits=0o077, links=1, max_size=1024 * 1024)
_FILES = frozenset(
    (
        "outcome",
        "outcome.sig",
        "deployment",
        "deployment.sig",
        "deployers.allowed_signers",
        "decision",
    )
)
_SOURCE_FILES = (
    "deployment",
    "deployment.sig",
    "deployers.allowed_signers",
    "decision",
)
_OUTCOME_SPEC = RecordSpec(CSR_OUTCOME_FIELDS, schema="1")
_REQUEST_ID = re.compile(r"[0-9a-f]{32}", re.ASCII)
_DIGEST = re.compile(r"[0-9a-f]{64}", re.ASCII)
_SIGNATURE_NAMESPACE = "platform-pki-csr-outcome-v1"


def _die(message: str) -> NoReturn:
    raise ApplicationError(message)


def _history(call):
    try:
        return call()
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
        _die(f"Cannot stage CSR outcome export member: {name}")
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _ensure_directory(parent: OpenedDirectory, name: str, path: str) -> OpenedDirectory:
    if parent.identity_at(name) is ABSENT:
        try:
            os.mkdir(name, 0o700, dir_fd=parent.fileno())
            fsync_directory(parent)
        except OSError:
            _die(f"Cannot create CSR outcome export directory: {path}")
    try:
        return parent.open_directory(name, policy=_DIRECTORY)
    except FilesystemError:
        _die(f"CSR outcome export directory is unsafe: {path}")


def _prepare_parent(pki_dir: str, service: str) -> OpenedDirectory:
    current: OpenedDirectory | None = None
    try:
        current = OpenedDirectory(pki_dir, policy=_DIRECTORY)
        path = pki_dir
        for name in ("export", "csr-outcomes", "v1", "artifacts", service):
            path = f"{path}/{name}"
            child = _ensure_directory(current, name, path)
            current.close()
            current = child
        return current
    except FilesystemError:
        if current is not None:
            current.close()
        _die("Cannot prepare CSR outcome export directory")


def _parent_path(pki_dir: str, service: str) -> str:
    return f"{pki_dir}/export/csr-outcomes/v1/artifacts/{service}"


def _open_parent(pki_dir: str, service: str) -> OpenedDirectory:
    current: OpenedDirectory | None = None
    try:
        current = OpenedDirectory(pki_dir, policy=_DIRECTORY)
        for name in ("export", "csr-outcomes", "v1", "artifacts", service):
            child = current.open_directory(name, policy=_DIRECTORY)
            current.close()
            current = child
        return current
    except FilesystemError:
        if current is not None:
            current.close()
        _die("CSR outcome export directory is unavailable or unsafe")


def _recheck_parent_path(path: str, parent: OpenedDirectory) -> None:
    try:
        current_identity = identity_from_stat(os.fstat(parent.fileno()))
        _DIRECTORY.validate(current_identity)
        if current_identity.directory != parent.directory_identity:
            _die("CSR outcome export parent path changed during validation")
        with OpenedDirectory(
            path, policy=_DIRECTORY, expected_identity=parent.directory_identity
        ) as current:
            current.recheck()
        if identity_from_stat(os.fstat(parent.fileno())).directory != parent.directory_identity:
            _die("CSR outcome export parent path changed during validation")
    except FilesystemError:
        _die("CSR outcome export parent path changed during validation")


def _manifest(
    service: str, request_id: str, source: CsrOutcomeExportAuthentication
) -> bytes:
    decision = source.history.decision
    values = {
        "schema": "1",
        "kind": "csr-signer-outcome",
        "service": service,
        "target": decision["target"],
        "request_id": request_id,
        "operation": decision["operation"],
        "request_sha256": decision["request_sha256"],
        "response_sha256": decision["response_sha256"],
        "response_signature_sha256": decision["response_signature_sha256"],
        "candidate_sha256": decision["candidate_sha256"],
        "artifact_manifest_sha256": decision["artifact_manifest_sha256"],
        "certificate_sha256": decision["certificate_sha256"],
        "certificate_spki_sha256": decision["certificate_spki_sha256"],
        "chain_sha256": decision["chain_sha256"],
        "fullchain_sha256": decision["fullchain_sha256"],
        "deployment_sha256": decision["deployment_sha256"],
        "deployment_signature_sha256": decision["deployment_signature_sha256"],
        "deployers_sha256": decision["deployers_sha256"],
        "decision_sha256": source.history.decision_sha256,
        "action": decision["action"],
        "state": decision["state"],
        "resulting_active_request_id": decision["resulting_active_request_id"],
        "created_epoch": decision["created_epoch"],
        "outcome_principal": source.outcome_principal,
    }
    try:
        return _OUTCOME_SPEC.serialize(values)
    except RecordError:
        _die("Cannot serialize CSR outcome export manifest")


def _run_keygen(
    argv: tuple[str, ...],
    environment: Mapping[str, str],
    *,
    input: bytes | None = None,
    pass_fds: tuple[int, ...] = (),
    prompt: bytes = b"OpenSSH outcome key passphrase: ",
) -> ProcessResult:
    try:
        result = run_ssh_keygen(
            argv,
            environment,
            input=input,
            pass_fds=pass_fds,
            passphrase_prompt=prompt,
        )
    except ApplicationError:
        _die("OpenSSH outcome signature operation failed")
    assert isinstance(result, ProcessResult)
    return result


def _open_outcome_key(
    key_path: str,
    source: CsrOutcomeExportAuthentication,
    environment: Mapping[str, str],
) -> tuple[OpenedFile, FileIdentity]:
    key: OpenedFile | None = None
    try:
        key = OpenedFile(key_path, policy=_KEY_FILE)
        if key.identity.size == 0:
            _die("CSR outcome signing key is empty")
        result = _run_keygen(
            ("ssh-keygen", "-y", "-f", f"/proc/self/fd/{key.fileno()}"),
            environment,
            pass_fds=(key.fileno(),),
            prompt=b"OpenSSH outcome key passphrase (verify retained trust): ",
        )
        fields = result.stdout.decode("ascii", errors="replace").strip().split()
        if result.status or len(fields) < 2 or fields[:2] != [
            "ssh-ed25519",
            source.outcome_public_key,
        ]:
            _die("CSR outcome signing key does not match the retained response signer")
        identity = key.recheck()
        return key, identity
    except FilesystemError:
        if key is not None:
            key.close()
        _die("CSR outcome signing key must be a safe current-user-owned private key")
    except BaseException:
        if key is not None:
            key.close()
        raise


def _recheck_key_path(key_path: str, identity: FileIdentity) -> None:
    try:
        with OpenedFile(key_path, policy=_KEY_FILE, expected_identity=identity) as key:
            key.recheck()
    except FilesystemError:
        _die("CSR outcome signing key changed during signing")


def _protect_signature(stage: OpenedDirectory) -> FileIdentity:
    descriptor = -1
    try:
        descriptor = os.open(
            "outcome.sig", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=stage.fileno()
        )
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        identity = identity_from_stat(os.fstat(descriptor))
        _FILE.validate(identity)
        if identity.size == 0 or stage.identity_at("outcome.sig") != identity:
            raise OSError("signature identity mismatch")
        return identity
    except (OSError, FilesystemError):
        _die("CSR outcome export signature could not be protected")
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _verify_signature(
    directory: OpenedDirectory,
    files: Mapping[str, FileIdentity],
    source: CsrOutcomeExportAuthentication,
    environment: Mapping[str, str],
) -> None:
    try:
        with OpenedFile(
            source.response_trust_path,
            policy=_FILE,
            expected_identity=source.response_trust_identity,
        ) as trust, directory.open_file(
            "outcome", policy=_FILE, expected_identity=files["outcome"]
        ) as outcome, directory.open_file(
            "outcome.sig", policy=_FILE, expected_identity=files["outcome.sig"]
        ) as signature:
            data = outcome.read(_FILE.max_size or 0)
            result = run_process(
                (
                    "ssh-keygen",
                    "-Y",
                    "verify",
                    "-f",
                    f"/proc/self/fd/{trust.fileno()}",
                    "-I",
                    source.outcome_principal,
                    "-n",
                    _SIGNATURE_NAMESPACE,
                    "-s",
                    f"/proc/self/fd/{signature.fileno()}",
                ),
                env=environment,
                input=data,
                pass_fds=(trust.fileno(), signature.fileno()),
                timeout=30.0,
                term_grace=1.0,
                stdout_limit=1024 * 1024,
                stderr_limit=1024 * 1024,
            )
            if not isinstance(result, ProcessResult) or result.status:
                _die("CSR outcome export signature verification failed")
            trust.recheck()
            outcome.recheck()
            signature.recheck()
    except FilesystemError:
        _die("CSR outcome export signature or retained trust changed")


def _create_stage(
    parent: OpenedDirectory,
    request_id: str,
    source: CsrOutcomeExportAuthentication,
    manifest: bytes,
    key_path: str,
    environment: Mapping[str, str],
) -> tuple[str, OpenedDirectory, FileIdentity, TreeReadiness]:
    for _attempt in range(16):
        name = f".platform-pki-csr-outcome-export.{request_id}.{secrets.token_hex(16)}"
        try:
            os.mkdir(name, 0o700, dir_fd=parent.fileno())
            break
        except FileExistsError:
            continue
        except OSError:
            _die("Cannot create CSR outcome export stage")
    else:
        _die("Cannot create CSR outcome export stage")
    stage: OpenedDirectory | None = None
    identity: FileIdentity | None = None
    readiness: TreeReadiness | None = None
    try:
        stage = parent.open_directory(name, policy=_DIRECTORY)
        files: dict[str, FileIdentity] = {
            "outcome": _write_file(stage, "outcome", manifest)
        }
        for file_name in _SOURCE_FILES:
            files[file_name] = _write_file(stage, file_name, source.files[file_name])
        key, key_identity = _open_outcome_key(key_path, source, environment)
        try:
            source()
            result = _run_keygen(
                (
                    "ssh-keygen",
                    "-Y",
                    "sign",
                    "-f",
                    f"/proc/self/fd/{key.fileno()}",
                    "-n",
                    _SIGNATURE_NAMESPACE,
                    f"/proc/self/fd/{stage.fileno()}/outcome",
                ),
                environment,
                pass_fds=(key.fileno(), stage.fileno()),
                prompt=b"OpenSSH outcome key passphrase (sign outcome): ",
            )
            if result.status:
                _die("CSR outcome export signing failed")
            key.recheck()
        finally:
            key.close()
        _recheck_key_path(key_path, key_identity)
        files["outcome.sig"] = _protect_signature(stage)
        if frozenset(os.listdir(stage.fileno())) != _FILES:
            _die("Staged CSR outcome export has unexpected entries")
        _verify_signature(stage, files, source, environment)
        source()
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
            print(
                "[WARN] CSR outcome export staging evidence retained for inspection: "
                f"{os.path.realpath(f'/proc/self/fd/{parent.fileno()}')}/{name}",
                file=sys.stderr,
                flush=True,
            )
        raise


def _load_artifact(
    parent: OpenedDirectory,
    name: str,
    path: str,
    service: str,
    request_id: str,
    source: CsrOutcomeExportAuthentication,
    environment: Mapping[str, str],
    expected_digest: str | None = None,
) -> tuple[OpenedDirectory, FileIdentity, Mapping[str, FileIdentity], str, OrderedRecord]:
    directory: OpenedDirectory | None = None
    try:
        identity = parent.identity_at(name)
        if (
            not isinstance(identity, FileIdentity)
            or identity.kind != "directory"
        ):
            _die(f"CSR outcome export has unexpected or unsafe entries: {path}")
        directory = parent.open_directory(
            name, policy=_DIRECTORY, expected_identity=identity
        )
        if frozenset(os.listdir(directory.fileno())) != _FILES:
            directory.close()
            _die(f"CSR outcome export has unexpected or unsafe entries: {path}")
        files: dict[str, FileIdentity] = {}
        data: dict[str, bytes] = {}
        for name in sorted(_FILES):
            with directory.open_file(name, policy=_FILE) as opened:
                data[name] = opened.read(_FILE.max_size or 0)
                files[name] = opened.recheck()
        directory.recheck()
    except FilesystemError:
        if directory is not None:
            directory.close()
        _die(f"CSR outcome export has unexpected or unsafe entries: {path}")
    try:
        record = _OUTCOME_SPEC.parse(data["outcome"])
    except RecordError as error:
        directory.close()
        _die(f"CSR outcome export manifest is invalid: {error}")
    if record.to_bytes() != _manifest(service, request_id, source):
        directory.close()
        _die("CSR outcome export manifest binding failed")
    expected_files = {
        "deployment": source.history.deployment_sha256,
        "deployment.sig": source.history.deployment_signature_sha256,
        "deployers.allowed_signers": source.history.deployers_sha256,
        "decision": source.history.decision_sha256,
    }
    if any(
        hashlib.sha256(data[name]).hexdigest() != digest
        for name, digest in expected_files.items()
    ):
        directory.close()
        _die("CSR outcome export file digest validation failed")
    if any(data[name] != source.files[name] for name in _SOURCE_FILES):
        directory.close()
        _die("CSR outcome export differs from authenticated signer outcome source")
    _verify_signature(directory, files, source, environment)
    digest = hashlib.sha256(data["outcome"]).hexdigest()
    if expected_digest is not None and digest != expected_digest:
        directory.close()
        _die("CSR outcome export manifest digest does not match --manifest-sha256")
    source()
    try:
        directory.recheck()
        for name, expected in files.items():
            with directory.open_file(name, policy=_FILE, expected_identity=expected) as opened:
                opened.recheck()
    except FilesystemError:
        directory.close()
        _die("CSR outcome export changed after validation")
    return directory, identity, files, digest, record


def _recheck_artifact(
    directory: OpenedDirectory,
    identity: FileIdentity,
    files: Mapping[str, FileIdentity],
) -> None:
    try:
        if directory.recheck() != identity:
            _die("CSR outcome export directory identity changed after validation")
        for name, expected in files.items():
            with directory.open_file(
                name, policy=_FILE, expected_identity=expected
            ) as opened:
                opened.recheck()
    except FilesystemError:
        _die("CSR outcome export changed after validation")


def _result(status: str, service: str, request_id: str, path: str, digest: str) -> None:
    print(
        json.dumps(
            {
                "status": status,
                "service": service,
                "request_id": request_id,
                "path": path,
                "manifest_sha256": digest,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )


def _publish(
    pki_dir: str,
    service: str,
    request_id: str,
    source: CsrOutcomeExportAuthentication,
    key_path: str,
    environment: Mapping[str, str],
    pause: PauseHook,
) -> int:
    parent = _prepare_parent(pki_dir, service)
    parent_path = _parent_path(pki_dir, service)
    path = f"{parent_path}/{request_id}"
    try:
        destination = parent.identity_at(request_id)
        if destination is not ABSENT:
            if not isinstance(destination, FileIdentity) or destination.kind != "directory":
                _die("CSR outcome export destination is unsafe")
            key, key_identity = _open_outcome_key(key_path, source, environment)
            key.close()
            _recheck_key_path(key_path, key_identity)
            artifact, identity, files, digest, _record = _load_artifact(
                parent, request_id, path, service, request_id, source, environment
            )
            try:
                pause("publish-existing-before-output")
                _recheck_artifact(artifact, identity, files)
                source()
                _recheck_parent_path(parent_path, parent)
            finally:
                artifact.close()
            _result("existing", service, request_id, path, digest)
            return 0
        manifest = _manifest(service, request_id, source)
        stage_name, stage, stage_identity, readiness = _create_stage(
            parent, request_id, source, manifest, key_path, environment
        )
        published = False
        raced_existing: tuple[
            OpenedDirectory,
            FileIdentity,
            Mapping[str, FileIdentity],
            str,
            OrderedRecord,
        ] | None = None
        try:
            pause("publish-before-rename")
            source()
            publish_no_clobber(
                parent,
                stage_name,
                stage_identity,
                parent,
                request_id,
                readiness=readiness,
                pre_publish_check=source,
            )
            published = True
        except PublicationDestinationExistsError:
            raced_existing = _load_artifact(
                parent,
                request_id,
                path,
                service,
                request_id,
                source,
                environment,
            )
        except PublicationAmbiguousError:
            _die("CSR outcome export publication requires inspection")
        except PublicationError as error:
            _die(str(error))
        finally:
            stage.close()
            if not published:
                try:
                    remove_exact_tree(parent, stage_name, stage_identity, readiness)
                except PublicationError:
                    print(
                        "[WARN] CSR outcome export staging evidence retained for inspection: "
                        f"{os.path.realpath(f'/proc/self/fd/{parent.fileno()}')}/{stage_name}",
                        file=sys.stderr,
                        flush=True,
                    )
        if raced_existing is not None:
            artifact, identity, files, digest, _record = raced_existing
            try:
                pause("publish-race-before-output")
                _recheck_artifact(artifact, identity, files)
                source()
                _recheck_parent_path(parent_path, parent)
            finally:
                artifact.close()
            _result("existing", service, request_id, path, digest)
            return 0
        artifact, identity, files, digest, _record = _load_artifact(
            parent, request_id, path, service, request_id, source, environment
        )
        try:
            pause("publish-created-before-output")
            _recheck_artifact(artifact, identity, files)
            source()
            _recheck_parent_path(parent_path, parent)
        finally:
            artifact.close()
        _result("created", service, request_id, path, digest)
        return 0
    finally:
        parent.close()


def _resolve(
    pki_dir: str,
    service: str,
    request_id: str,
    source: CsrOutcomeExportAuthentication,
    environment: Mapping[str, str],
    digest: str,
    output_format: str,
    pause: PauseHook,
) -> int:
    if _DIGEST.fullmatch(digest) is None:
        _die("--manifest-sha256 must be a lowercase SHA-256 digest")
    parent_path = _parent_path(pki_dir, service)
    path = f"{parent_path}/{request_id}"
    parent = _open_parent(pki_dir, service)
    try:
        artifact, identity, files, actual, record = _load_artifact(
            parent,
            request_id,
            path,
            service,
            request_id,
            source,
            environment,
            digest,
        )
    except BaseException:
        parent.close()
        raise
    try:
        absolute = os.path.realpath(f"/proc/self/fd/{artifact.fileno()}")
        pause("resolver-before-output")
        _recheck_artifact(artifact, identity, files)
        source()
        _recheck_parent_path(parent_path, parent)
        if output_format == "path":
            print(absolute)
        else:
            print(
                json.dumps(
                    {
                        "schema": 1,
                        "kind": "csr-outcome-export-resolution",
                        "service": service,
                        "request_id": request_id,
                        "manifest_sha256": actual,
                        "path": absolute,
                        "action": record["action"],
                        "state": record["state"],
                        "live_target_state_claimed": False,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
        return 0
    finally:
        artifact.close()
        parent.close()


def csr_outcome(parsed: ParseResult) -> int:
    """Publish or resolve one authenticated terminal CSR signer outcome."""

    environment = dict(os.environ)
    os.umask(0o077)
    service_name = parsed["service"]
    request_id = parsed["--request-id"]
    validate_service_name(service_name)
    if _REQUEST_ID.fullmatch(request_id) is None:
        _die("CSR outcome export request ID is invalid")
    key_path: str | None = None
    if parsed.spec.route == ("csr-outcome", "publish"):
        key_path = parsed["--outcome-key"]
        try:
            validate_absolute_path(key_path)
        except PathError as error:
            _die(f"CSR outcome signing key path is invalid: {error.message}")
    for program in ("openssl", "ssh-keygen"):
        require_program(program, environment)
    paths = resolve_paths(parsed.values, environment)
    require_pki_directory(paths.pki_dir)
    prepare_control_state(paths.pki_dir)
    pause = PauseHook(
        pause_at=environment.get("PLATFORM_PKI_CSR_OUTCOME_PAUSE_AT"),
        marker=environment.get("PLATFORM_PKI_CSR_OUTCOME_PAUSE_MARKER"),
        release=environment.get("PLATFORM_PKI_CSR_OUTCOME_PAUSE_RELEASE"),
    )
    with acquire_operational_locks(paths.pki_dir, "export"):
        require_no_unresolved_state(paths.pki_dir)
        require_generation_layout(paths.pki_dir)
        inventory_path = require_inventory_readable(paths.pki_dir)
        inventory = load_inventory(inventory_path)
        service = get_service(inventory, service_name, inventory_path)
        if service.key_custody != "host-local":
            _die("CSR outcome export requires key_custody: host-local")
        source = _history(
            lambda: authenticate_outcome_export_source(
                paths.pki_dir, service, request_id, environment
            )
        )
        assert isinstance(source, CsrOutcomeExportAuthentication)
        if parsed.spec.route == ("csr-outcome", "publish"):
            assert key_path is not None
            return _publish(
                paths.pki_dir,
                service_name,
                request_id,
                source,
                key_path,
                environment,
                pause,
            )
        return _resolve(
            paths.pki_dir,
            service_name,
            request_id,
            source,
            environment,
            parsed["--manifest-sha256"],
            parsed["--format"],
            pause,
        )
